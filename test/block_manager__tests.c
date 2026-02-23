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
    ASSERT_TRUE(block_manager_validate_last_block(bm, BLOCK_MANAGER_PERMISSIVE_BLOCK_VALIDATION) ==
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
        {1000, 1024},   /* 1K blocks (1KB each) */
        {5000, 1024},   /* 5K blocks (1KB each) */
        {10000, 1024},  /* 10K blocks (1KB each) */
        {20000, 1024},  /* 20K blocks (1KB each) */
        {10000, 65536}, /* 10K blocks (64KB each) */
    };

    for (size_t config = 0; config < sizeof(test_configs) / sizeof(test_configs[0]); config++)
    {
        int num_blocks = test_configs[config][0];
        int block_size = test_configs[config][1];

        block_manager_truncate(bm);

        printf("\n" BOLDWHITE "Config: %d blocks × %d bytes\n" RESET, num_blocks, block_size);

        uint8_t *data = malloc(block_size);
        memset(data, 'X', block_size);

        struct timespec write_start;
        clock_gettime(CLOCK_MONOTONIC, &write_start);

        for (int i = 0; i < num_blocks; i++)
        {
            block_manager_block_t *block = block_manager_block_create(block_size, data);
            block_manager_block_write(bm, block);
            block_manager_block_free(block);
        }
        free(data);

        struct timespec write_end;
        clock_gettime(CLOCK_MONOTONIC, &write_end);
        double write_elapsed = (write_end.tv_sec - write_start.tv_sec) +
                               (write_end.tv_nsec - write_start.tv_nsec) / 1e9;
        double write_throughput = num_blocks / write_elapsed;
        double write_mb = (write_throughput * block_size) / (1024.0 * 1024.0);

        printf("  Write phase:\n");
        printf("    Time: %.3f seconds\n", write_elapsed);
        printf("    Throughput: %.2f blocks/sec (%.2f MB/sec)\n", write_throughput, write_mb);

        block_manager_close(bm);
        ASSERT_TRUE(block_manager_open(&bm, "iteration_bench.db", BLOCK_MANAGER_SYNC_NONE) == 0);

        /* Phase 2: cursor_next iteration only (no data read) */
        block_manager_cursor_t *cursor;
        ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);

        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);

        int blocks_iterated = 0;
        ASSERT_TRUE(block_manager_cursor_goto_first(cursor) == 0);
        do
        {
            blocks_iterated++;
        } while (block_manager_cursor_next(cursor) == 0);

        clock_gettime(CLOCK_MONOTONIC, &end);
        double iter_elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
        double iter_throughput = blocks_iterated / iter_elapsed;
        double iter_mb = (iter_throughput * block_size) / (1024.0 * 1024.0);

        printf("  Iterate-only (cursor_next, no read):\n");
        printf("    Blocks: %d | Time: %.3f s\n", blocks_iterated, iter_elapsed);
        printf("    Throughput: %.2f blocks/sec (%.2f MB/sec)\n", iter_throughput, iter_mb);
        printf("    Avg latency: %.2f μs/block\n", (iter_elapsed / blocks_iterated) * 1e6);

        block_manager_cursor_free(cursor);

        /* Phase 3: full read + verify (cursor_read every block) */
        block_manager_cursor_t *read_cursor;
        ASSERT_TRUE(block_manager_cursor_init(&read_cursor, bm) == 0);

        clock_gettime(CLOCK_MONOTONIC, &start);

        int blocks_read = 0;
        ASSERT_TRUE(block_manager_cursor_goto_first(read_cursor) == 0);
        do
        {
            block_manager_block_t *blk = block_manager_cursor_read(read_cursor);
            if (blk)
            {
                blocks_read++;
                block_manager_block_free(blk);
            }
        } while (block_manager_cursor_next(read_cursor) == 0);

        clock_gettime(CLOCK_MONOTONIC, &end);
        double read_elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
        double read_throughput = blocks_read / read_elapsed;
        double read_mb = (read_throughput * block_size) / (1024.0 * 1024.0);

        printf("  Read+verify (cursor_read every block):\n");
        printf("    Blocks: %d | Time: %.3f s\n", blocks_read, read_elapsed);
        printf("    Throughput: %.2f blocks/sec (%.2f MB/sec)\n", read_throughput, read_mb);
        printf("    Avg latency: %.2f μs/block\n", (read_elapsed / blocks_read) * 1e6);

        block_manager_cursor_free(read_cursor);
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

void test_block_manager_concurrent_file_extension()
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, "test_concurrent_ext.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    /* write blocks with varying sizes that will cause file extension.
     * this mimics the WAL scenario where entries have different sizes. */
    const int num_blocks = 50;
    char **expected_data = malloc(num_blocks * sizeof(char *));
    size_t *expected_sizes = malloc(num_blocks * sizeof(size_t));

    for (int i = 0; i < num_blocks; i++)
    {
        /* vary block sizes to create different extension scenarios */
        size_t data_size = 100 + (i * 50); /* increasing sizes 100, 150, 200, ... */
        expected_data[i] = malloc(data_size);
        expected_sizes[i] = data_size;

        /* fill with pattern that includes block number for verification */
        for (size_t j = 0; j < data_size; j++)
        {
            expected_data[i][j] = (char)((i + j) % 256);
        }
        /* we add a marker at the end */
        snprintf(expected_data[i] + data_size - 20, 20, "_block_%d_end", i);

        block_manager_block_t *block = block_manager_block_create(data_size, expected_data[i]);
        ASSERT_TRUE(block != NULL);

        int64_t offset = block_manager_block_write(bm, block);
        ASSERT_TRUE(offset >= 0);

        block_manager_block_free(block);
    }

    /* close and reopen to force recovery/validation */
    ASSERT_TRUE(block_manager_close(bm) == 0);
    ASSERT_TRUE(block_manager_open(&bm, "test_concurrent_ext.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    /* verify all blocks were written correctly */
    block_manager_cursor_t *cursor;
    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);
    ASSERT_TRUE(block_manager_cursor_goto_first(cursor) == 0);

    for (int i = 0; i < num_blocks; i++)
    {
        block_manager_block_t *read_block = block_manager_cursor_read(cursor);
        ASSERT_TRUE(read_block != NULL);
        ASSERT_EQ(read_block->size, expected_sizes[i]);

        /* verify the marker at the end to confirm correct block */
        char marker[20];
        snprintf(marker, 20, "_block_%d_end", i);

        char *actual_marker = (char *)(read_block->data) + expected_sizes[i] - 20;
        size_t marker_len = strlen(marker);

        if (memcmp(actual_marker, marker, marker_len) != 0)
        {
            printf("\nBlock %d marker mismatch:\n", i);
            printf("  Expected (%zu bytes): '%s'\n", marker_len, marker);
            printf("  Actual: '");
            for (size_t k = 0; k < marker_len && k < 20; k++)
            {
                printf("%c", actual_marker[k]);
            }
            printf("'\n");
            printf("  Hex comparison:\n    Expected: ");
            for (size_t k = 0; k < marker_len; k++)
            {
                printf("%02x ", (unsigned char)marker[k]);
            }
            printf("\n    Actual:   ");
            for (size_t k = 0; k < marker_len; k++)
            {
                printf("%02x ", (unsigned char)actual_marker[k]);
            }
            printf("\n");
        }

        ASSERT_EQ(memcmp(actual_marker, marker, marker_len), 0);

        /* verify the pattern in the first part (before the marker) */
        int pattern_ok = 1;
        uint8_t *data_bytes = (uint8_t *)read_block->data;
        for (size_t j = 0; j < expected_sizes[i] - 20; j++)
        {
            if (data_bytes[j] != (uint8_t)((i + j) % 256))
            {
                pattern_ok = 0;
                break;
            }
        }
        ASSERT_TRUE(pattern_ok);

        block_manager_block_free(read_block);

        if (i < num_blocks - 1)
        {
            ASSERT_TRUE(block_manager_cursor_next(cursor) == 0);
        }
    }

    for (int i = 0; i < num_blocks; i++)
    {
        free(expected_data[i]);
    }
    free(expected_data);
    free(expected_sizes);

    block_manager_cursor_free(cursor);
    ASSERT_TRUE(block_manager_close(bm) == 0);
    (void)remove("test_concurrent_ext.db");
}

typedef struct
{
    block_manager_t *bm;
    int thread_id;
    int num_blocks;
    int *success_count;
    pthread_mutex_t *mutex;
} concurrent_write_args_t;

static void *concurrent_write_thread(void *arg)
{
    concurrent_write_args_t *args = (concurrent_write_args_t *)arg;
    int local_success = 0;

    for (int i = 0; i < args->num_blocks; i++)
    {
        char data[64];
        snprintf(data, sizeof(data), "thread_%d_block_%d_data", args->thread_id, i);
        size_t data_size = strlen(data) + 1;

        block_manager_block_t *block = block_manager_block_create(data_size, data);
        if (!block) continue;

        int64_t offset = block_manager_block_write(args->bm, block);
        block_manager_block_free(block);

        if (offset >= 0)
        {
            local_success++;
        }
    }

    pthread_mutex_lock(args->mutex);
    *args->success_count += local_success;
    pthread_mutex_unlock(args->mutex);

    return NULL;
}

#define CONCURRENT_TEST_NUM_THREADS       4
#define CONCURRENT_TEST_BLOCKS_PER_THREAD 50

void test_block_manager_concurrent_write_size_reopen()
{
    const char *test_file = "test_concurrent_size_reopen.db";
    const int num_threads = CONCURRENT_TEST_NUM_THREADS;
    const int blocks_per_thread = CONCURRENT_TEST_BLOCKS_PER_THREAD;
    const int total_expected_blocks = num_threads * blocks_per_thread;

    (void)remove(test_file);

    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, test_file, BLOCK_MANAGER_SYNC_FULL) == 0);

    /* get initial file size (should be just header) */
    uint64_t initial_size;
    ASSERT_TRUE(block_manager_get_size(bm, &initial_size) == 0);
    printf("Initial file size: %" PRIu64 " bytes\n", initial_size);
    ASSERT_EQ(initial_size, BLOCK_MANAGER_HEADER_SIZE);

    /* spawn concurrent writer threads */
    pthread_t threads[CONCURRENT_TEST_NUM_THREADS];
    concurrent_write_args_t args[CONCURRENT_TEST_NUM_THREADS];
    int success_count = 0;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

    for (int i = 0; i < num_threads; i++)
    {
        args[i].bm = bm;
        args[i].thread_id = i;
        args[i].num_blocks = blocks_per_thread;
        args[i].success_count = &success_count;
        args[i].mutex = &mutex;
        ASSERT_TRUE(pthread_create(&threads[i], NULL, concurrent_write_thread, &args[i]) == 0);
    }

    /* wait for all threads to complete */
    for (int i = 0; i < num_threads; i++)
    {
        ASSERT_TRUE(pthread_join(threads[i], NULL) == 0);
    }

    pthread_mutex_destroy(&mutex);

    printf("Successfully wrote %d blocks (expected %d)\n", success_count, total_expected_blocks);
    ASSERT_EQ(success_count, total_expected_blocks);

    /* verify file size after writes */
    uint64_t size_after_writes;
    ASSERT_TRUE(block_manager_get_size(bm, &size_after_writes) == 0);
    printf("File size after writes: %" PRIu64 " bytes\n", size_after_writes);
    ASSERT_TRUE(size_after_writes > initial_size);

    /* count blocks to verify */
    int block_count = block_manager_count_blocks(bm);
    printf("Block count after writes: %d (expected %d)\n", block_count, total_expected_blocks);
    ASSERT_EQ(block_count, total_expected_blocks);

    /* close the block manager */
    ASSERT_TRUE(block_manager_close(bm) == 0);

    /* reopen and verify file size is preserved */
    bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, test_file, BLOCK_MANAGER_SYNC_FULL) == 0);

    uint64_t size_after_reopen;
    ASSERT_TRUE(block_manager_get_size(bm, &size_after_reopen) == 0);
    printf("File size after reopen: %" PRIu64 " bytes\n", size_after_reopen);
    ASSERT_EQ(size_after_reopen, size_after_writes);

    /* verify block count after reopen */
    int block_count_after_reopen = block_manager_count_blocks(bm);
    printf("Block count after reopen: %d (expected %d)\n", block_count_after_reopen,
           total_expected_blocks);
    ASSERT_EQ(block_count_after_reopen, total_expected_blocks);

    /* verify all blocks are readable and have correct data */
    block_manager_cursor_t *cursor;
    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);
    ASSERT_TRUE(block_manager_cursor_goto_first(cursor) == 0);

    int readable_blocks = 0;
    int thread_counts[CONCURRENT_TEST_NUM_THREADS];
    memset(thread_counts, 0, sizeof(thread_counts));

    do
    {
        block_manager_block_t *block = block_manager_cursor_read(cursor);
        if (!block) break;

        /* parse thread_id from block data */
        char *data = (char *)block->data;
        int thread_id = -1;
        if (sscanf(data, "thread_%d_block_", &thread_id) == 1 && thread_id >= 0 &&
            thread_id < num_threads)
        {
            thread_counts[thread_id]++;
        }

        readable_blocks++;
        block_manager_block_free(block);
    } while (block_manager_cursor_next(cursor) == 0);

    block_manager_cursor_free(cursor);

    printf("Readable blocks after reopen: %d (expected %d)\n", readable_blocks,
           total_expected_blocks);
    ASSERT_EQ(readable_blocks, total_expected_blocks);

    /* verify each thread wrote the expected number of blocks */
    for (int i = 0; i < num_threads; i++)
    {
        printf("Thread %d wrote %d blocks (expected %d)\n", i, thread_counts[i], blocks_per_thread);
        ASSERT_EQ(thread_counts[i], blocks_per_thread);
    }

    ASSERT_TRUE(block_manager_close(bm) == 0);
    (void)remove(test_file);
}

void test_block_manager_block_write_batch(void)
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, "test_batch.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    /* we create multiple blocks */
    const int num_blocks = 5;
    block_manager_block_t *blocks[5];
    int64_t offsets[5];
    char data[5][32];

    for (int i = 0; i < num_blocks; i++)
    {
        snprintf(data[i], 32, "batch_block_data_%d", i);
        blocks[i] = block_manager_block_create(strlen(data[i]) + 1, data[i]);
        ASSERT_TRUE(blocks[i] != NULL);
    }

    /* we write all blocks in one batch */
    int result = block_manager_block_write_batch(bm, blocks, num_blocks, offsets);
    ASSERT_EQ(result, num_blocks);

    /* we verify all offsets are valid and increasing */
    for (int i = 0; i < num_blocks; i++)
    {
        ASSERT_TRUE(offsets[i] >= 0);
        if (i > 0)
        {
            ASSERT_TRUE(offsets[i] > offsets[i - 1]);
        }
    }

    /* we free the blocks */
    for (int i = 0; i < num_blocks; i++)
    {
        block_manager_block_free(blocks[i]);
    }

    /* we close and reopen to verify persistence */
    ASSERT_TRUE(block_manager_close(bm) == 0);
    ASSERT_TRUE(block_manager_open(&bm, "test_batch.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    /* we read back and verify all blocks */
    block_manager_cursor_t *cursor = NULL;
    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);

    int blocks_read = 0;
    do
    {
        block_manager_block_t *block = block_manager_cursor_read(cursor);
        if (block)
        {
            char expected[32];
            snprintf(expected, 32, "batch_block_data_%d", blocks_read);
            ASSERT_EQ(strcmp((char *)block->data, expected), 0);
            block_manager_block_free(block);
            blocks_read++;
        }
    } while (block_manager_cursor_next(cursor) == 0);

    block_manager_cursor_free(cursor);
    ASSERT_EQ(blocks_read, num_blocks);

    ASSERT_TRUE(block_manager_close(bm) == 0);
    remove("test_batch.db");
}

void test_block_manager_block_create_from_buffer(void)
{
    uint64_t size = 10;
    char *data = malloc(size);
    ASSERT_TRUE(data != NULL);
    memcpy(data, "frombuffer", size);

    block_manager_block_t *block = block_manager_block_create_from_buffer(size, data);
    ASSERT_TRUE(block != NULL);
    ASSERT_EQ(block->size, size);
    ASSERT_EQ(memcmp(block->data, "frombuffer", size), 0);

    /* block_free should free the buffer we passed in */
    block_manager_block_free(block);
}

void test_block_manager_write_at_and_update_checksum(void)
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, "test_write_at.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    /* write a block */
    char original[] = "original__";
    block_manager_block_t *block = block_manager_block_create(10, original);
    ASSERT_TRUE(block != NULL);
    int64_t offset = block_manager_block_write(bm, block);
    ASSERT_TRUE(offset >= 0);
    block_manager_block_free(block);

    /* patch data in-place using write_at (skip past block header) */
    const uint8_t patch[] = "patched___";
    int64_t data_offset = offset + BLOCK_MANAGER_BLOCK_HEADER_SIZE;
    ASSERT_EQ(block_manager_write_at(bm, data_offset, patch, 10), 0);

    /* update checksum to match new data */
    ASSERT_EQ(block_manager_update_checksum(bm, offset), 0);

    /* read back and verify */
    block_manager_cursor_t *cursor;
    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);
    ASSERT_TRUE(block_manager_cursor_goto(cursor, (uint64_t)offset) == 0);
    block_manager_block_t *read_block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(read_block != NULL);
    ASSERT_EQ(memcmp(read_block->data, "patched___", 10), 0);
    block_manager_block_free(read_block);

    block_manager_cursor_free(cursor);
    ASSERT_TRUE(block_manager_close(bm) == 0);
    remove("test_write_at.db");
}

void test_block_manager_block_acquire_release(void)
{
    block_manager_block_t *block = block_manager_block_create(5, "hello");
    ASSERT_TRUE(block != NULL);

    /* acquire should succeed */
    ASSERT_EQ(block_manager_block_acquire(block), 1);

    /* release once (ref_count 2 -> 1), block should still be alive */
    block_manager_block_release(block);

    /* we can still read data */
    ASSERT_EQ(memcmp(block->data, "hello", 5), 0);

    /* final release frees block (ref_count 1 -> 0) */
    block_manager_block_release(block);

    /* acquire on NULL should return 0 */
    ASSERT_EQ(block_manager_block_acquire(NULL), 0);
}

void test_block_manager_cursor_read_partial(void)
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, "test_partial.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    char data[100];
    memset(data, 'A', 100);
    block_manager_block_t *block = block_manager_block_create(100, data);
    ASSERT_TRUE(block != NULL);
    ASSERT_TRUE(block_manager_block_write(bm, block) >= 0);
    block_manager_block_free(block);

    block_manager_cursor_t *cursor;
    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);

    /* partial read with max_bytes < block size */
    block_manager_block_t *partial = block_manager_cursor_read_partial(cursor, 20);
    ASSERT_TRUE(partial != NULL);
    ASSERT_EQ(partial->size, 20);
    for (size_t i = 0; i < 20; i++)
    {
        ASSERT_EQ(((char *)partial->data)[i], 'A');
    }
    block_manager_block_free(partial);

    /* max_bytes=0 should read full block */
    block_manager_block_t *full = block_manager_cursor_read_partial(cursor, 0);
    ASSERT_TRUE(full != NULL);
    ASSERT_EQ(full->size, 100);
    block_manager_block_free(full);

    block_manager_cursor_free(cursor);
    ASSERT_TRUE(block_manager_close(bm) == 0);
    remove("test_partial.db");
}

void test_block_manager_cursor_read_and_advance(void)
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, "test_read_advance.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    for (int i = 0; i < 3; i++)
    {
        char data[10];
        snprintf(data, 10, "block_%d__", i);
        block_manager_block_t *block = block_manager_block_create(10, data);
        ASSERT_TRUE(block != NULL);
        ASSERT_TRUE(block_manager_block_write(bm, block) >= 0);
        block_manager_block_free(block);
    }

    block_manager_cursor_t *cursor;
    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);

    /* read_and_advance should return block and move cursor forward */
    block_manager_block_t *b0 = block_manager_cursor_read_and_advance(cursor);
    ASSERT_TRUE(b0 != NULL);
    ASSERT_EQ(memcmp(b0->data, "block_0__", 10), 0);
    block_manager_block_free(b0);

    block_manager_block_t *b1 = block_manager_cursor_read_and_advance(cursor);
    ASSERT_TRUE(b1 != NULL);
    ASSERT_EQ(memcmp(b1->data, "block_1__", 10), 0);
    block_manager_block_free(b1);

    block_manager_block_t *b2 = block_manager_cursor_read_and_advance(cursor);
    ASSERT_TRUE(b2 != NULL);
    ASSERT_EQ(memcmp(b2->data, "block_2__", 10), 0);
    block_manager_block_free(b2);

    /* next read_and_advance should return NULL (past end) */
    block_manager_block_t *b3 = block_manager_cursor_read_and_advance(cursor);
    ASSERT_TRUE(b3 == NULL);

    block_manager_cursor_free(cursor);
    ASSERT_TRUE(block_manager_close(bm) == 0);
    remove("test_read_advance.db");
}

void test_block_manager_escalate_fsync(void)
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, "test_fsync.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    block_manager_block_t *block = block_manager_block_create(5, "fsync");
    ASSERT_TRUE(block != NULL);
    ASSERT_TRUE(block_manager_block_write(bm, block) >= 0);
    block_manager_block_free(block);

    ASSERT_EQ(block_manager_escalate_fsync(bm), 0);
    ASSERT_EQ(block_manager_escalate_fsync(NULL), -1);

    ASSERT_TRUE(block_manager_close(bm) == 0);
    remove("test_fsync.db");
}

void test_block_manager_last_modified(void)
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, "test_mtime.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    time_t mtime = block_manager_last_modified(bm);
    ASSERT_TRUE(mtime > 0);
    ASSERT_EQ(block_manager_last_modified(NULL), -1);

    ASSERT_TRUE(block_manager_close(bm) == 0);
    remove("test_mtime.db");
}

void test_block_manager_set_sync_mode(void)
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, "test_setmode.db", BLOCK_MANAGER_SYNC_NONE) == 0);
    ASSERT_EQ(bm->sync_mode, BLOCK_MANAGER_SYNC_NONE);

    block_manager_set_sync_mode(bm, 1);
    ASSERT_EQ(bm->sync_mode, BLOCK_MANAGER_SYNC_FULL);

    block_manager_set_sync_mode(bm, 0);
    ASSERT_EQ(bm->sync_mode, BLOCK_MANAGER_SYNC_NONE);

    /* invalid mode should default to SYNC_NONE */
    block_manager_set_sync_mode(bm, 99);
    ASSERT_EQ(bm->sync_mode, BLOCK_MANAGER_SYNC_NONE);

    /* NULL bm should not crash */
    block_manager_set_sync_mode(NULL, 1);

    ASSERT_TRUE(block_manager_close(bm) == 0);
    remove("test_setmode.db");
}

void test_block_manager_get_block_size_at_offset(void)
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, "test_blksize.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    char data[50];
    memset(data, 'X', 50);
    block_manager_block_t *block = block_manager_block_create(50, data);
    ASSERT_TRUE(block != NULL);
    int64_t offset = block_manager_block_write(bm, block);
    ASSERT_TRUE(offset >= 0);
    block_manager_block_free(block);

    uint32_t size = 0;
    ASSERT_EQ(block_manager_get_block_size_at_offset(bm, (uint64_t)offset, &size), 0);
    ASSERT_EQ(size, 50);

    ASSERT_TRUE(block_manager_close(bm) == 0);
    remove("test_blksize.db");
}

void test_block_manager_read_at_offset(void)
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, "test_readat.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    char data[] = "read_at_test_data";
    block_manager_block_t *block = block_manager_block_create(strlen(data) + 1, data);
    ASSERT_TRUE(block != NULL);
    int64_t offset = block_manager_block_write(bm, block);
    ASSERT_TRUE(offset >= 0);
    block_manager_block_free(block);

    /* we read raw data at the data offset (past block header) */
    uint64_t data_offset = (uint64_t)offset + BLOCK_MANAGER_BLOCK_HEADER_SIZE;
    uint8_t buf[18];
    ASSERT_EQ(block_manager_read_at_offset(bm, data_offset, strlen(data) + 1, buf), 0);
    ASSERT_EQ(strcmp((char *)buf, data), 0);

    ASSERT_TRUE(block_manager_close(bm) == 0);
    remove("test_readat.db");
}

void test_block_manager_read_block_data_at_offset(void)
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, "test_readblk.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    char data[] = "block_data_offset";
    block_manager_block_t *block = block_manager_block_create(strlen(data) + 1, data);
    ASSERT_TRUE(block != NULL);
    int64_t offset = block_manager_block_write(bm, block);
    ASSERT_TRUE(offset >= 0);
    block_manager_block_free(block);

    uint8_t *out_data = NULL;
    uint32_t out_size = 0;
    ASSERT_EQ(block_manager_read_block_data_at_offset(bm, (uint64_t)offset, &out_data, &out_size),
              0);
    ASSERT_EQ(out_size, strlen(data) + 1);
    ASSERT_EQ(strcmp((char *)out_data, data), 0);
    free(out_data);

    ASSERT_TRUE(block_manager_close(bm) == 0);
    remove("test_readblk.db");
}

void test_block_manager_checksum_corruption(void)
{
    block_manager_t *bm = NULL;
    (void)remove("test_cksum.db");
    ASSERT_TRUE(block_manager_open(&bm, "test_cksum.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    block_manager_block_t *block = block_manager_block_create(10, "checksumok");
    ASSERT_TRUE(block != NULL);
    int64_t offset = block_manager_block_write(bm, block);
    ASSERT_TRUE(offset >= 0);
    block_manager_block_free(block);
    block_manager_escalate_fsync(bm);

    /* we corrupt the checksum field (4 bytes after size field) */
    uint8_t bad_cksum[4] = {0xFF, 0xFF, 0xFF, 0xFF};
    int64_t cksum_offset = offset + BLOCK_MANAGER_SIZE_FIELD_SIZE;
    ASSERT_EQ(block_manager_write_at(bm, cksum_offset, bad_cksum, 4), 0);

    /* cursor_read should fail due to checksum mismatch */
    block_manager_cursor_t *cursor;
    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);
    ASSERT_TRUE(block_manager_cursor_goto(cursor, (uint64_t)offset) == 0);
    block_manager_block_t *read_block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(read_block == NULL);

    block_manager_cursor_free(cursor);
    ASSERT_TRUE(block_manager_close(bm) == 0);
    remove("test_cksum.db");
}

void test_block_manager_header_corruption(void)
{
    (void)remove("test_hdr_corrupt.db");

    /* we create a valid file first */
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, "test_hdr_corrupt.db", BLOCK_MANAGER_SYNC_NONE) == 0);
    ASSERT_TRUE(block_manager_close(bm) == 0);

    /* we corrupt the magic bytes */
    FILE *f = fopen("test_hdr_corrupt.db", "r+b");
    ASSERT_TRUE(f != NULL);
    uint8_t garbage[3] = {0x00, 0x00, 0x00};
    fwrite(garbage, 1, 3, f);
    fclose(f);

    /* we open should fail because header magic is invalid */
    bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, "test_hdr_corrupt.db", BLOCK_MANAGER_SYNC_NONE) != 0);

    remove("test_hdr_corrupt.db");
}

void test_block_manager_strict_validation(void)
{
    (void)remove("test_strict.db");
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, "test_strict.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    for (int i = 0; i < 3; i++)
    {
        char data[10];
        snprintf(data, 10, "testdata%d", i);
        block_manager_block_t *block = block_manager_block_create(10, data);
        ASSERT_TRUE(block != NULL);
        ASSERT_TRUE(block_manager_block_write(bm, block) >= 0);
        block_manager_block_free(block);
    }
    block_manager_escalate_fsync(bm);
    ASSERT_TRUE(block_manager_close(bm) == 0);

    /* we append garbage to corrupt the file */
    FILE *f = fopen("test_strict.db", "a+b");
    ASSERT_TRUE(f != NULL);
    uint8_t junk[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    fwrite(junk, 1, 4, f);
    fclose(f);

    /* strict validation should fail */
    ASSERT_TRUE(block_manager_open(&bm, "test_strict.db", BLOCK_MANAGER_SYNC_NONE) == 0);
    ASSERT_TRUE(block_manager_validate_last_block(bm, BLOCK_MANAGER_STRICT_BLOCK_VALIDATION) != 0);
    ASSERT_TRUE(block_manager_close(bm) == 0);

    /* permissive validation should succeed and recover */
    ASSERT_TRUE(block_manager_open(&bm, "test_strict.db", BLOCK_MANAGER_SYNC_NONE) == 0);
    ASSERT_TRUE(block_manager_validate_last_block(bm, BLOCK_MANAGER_PERMISSIVE_BLOCK_VALIDATION) ==
                0);

    /* we should still have 3 readable blocks */
    ASSERT_EQ(block_manager_count_blocks(bm), 3);

    ASSERT_TRUE(block_manager_close(bm) == 0);
    remove("test_strict.db");
}

void test_block_manager_validate_zero_size_file(void)
{
    (void)remove("test_zero.db");

    /* we open a valid file, then externally truncate to 0 to simulate crash */
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, "test_zero.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    /* we truncate the underlying fd to 0 (simulates external corruption) */
    ASSERT_EQ(ftruncate(bm->fd, 0), 0);

    /* we validate should detect zero size and write header */
    ASSERT_EQ(block_manager_validate_last_block(bm, BLOCK_MANAGER_PERMISSIVE_BLOCK_VALIDATION), 0);

    uint64_t size;
    ASSERT_EQ(block_manager_get_size(bm, &size), 0);

    ASSERT_TRUE(block_manager_close(bm) == 0);
    remove("test_zero.db");
}

void test_block_manager_footer_corruption_mid_file(void)
{
    (void)remove("test_mid_corrupt.db");
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, "test_mid_corrupt.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    int64_t offsets[5];
    for (int i = 0; i < 5; i++)
    {
        char data[10];
        snprintf(data, 10, "testdata%d", i);
        block_manager_block_t *block = block_manager_block_create(10, data);
        ASSERT_TRUE(block != NULL);
        offsets[i] = block_manager_block_write(bm, block);
        ASSERT_TRUE(offsets[i] >= 0);
        block_manager_block_free(block);
    }
    block_manager_escalate_fsync(bm);
    ASSERT_TRUE(block_manager_close(bm) == 0);

    /*** we corrupt footer of both block 3 and block 4
     ** validate_last_block reads the last footer first (block 4) which triggers scan
     * scan walks forward and stops at block 3's corrupted footer -> 3 valid blocks */
    FILE *f = fopen("test_mid_corrupt.db", "r+b");
    ASSERT_TRUE(f != NULL);
    uint8_t bad_footer[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    /* we corrupt block 3 footer */
    long footer_pos3 = (long)(offsets[3] + BLOCK_MANAGER_BLOCK_HEADER_SIZE + 10);
    fseek(f, footer_pos3, SEEK_SET);
    fwrite(bad_footer, 1, 8, f);

    /* we corrupt block 4 footer (last block) to trigger the scan path */
    long footer_pos4 = (long)(offsets[4] + BLOCK_MANAGER_BLOCK_HEADER_SIZE + 10);
    fseek(f, footer_pos4, SEEK_SET);
    fwrite(bad_footer, 1, 8, f);

    fclose(f);

    /* permissive validation should recover to 3 blocks (blocks 0-2 valid) */
    ASSERT_TRUE(block_manager_open(&bm, "test_mid_corrupt.db", BLOCK_MANAGER_SYNC_NONE) == 0);
    ASSERT_EQ(block_manager_validate_last_block(bm, BLOCK_MANAGER_PERMISSIVE_BLOCK_VALIDATION), 0);
    ASSERT_EQ(block_manager_count_blocks(bm), 3);

    ASSERT_TRUE(block_manager_close(bm) == 0);
    remove("test_mid_corrupt.db");
}

void test_block_manager_convert_sync_mode(void)
{
    ASSERT_EQ(convert_sync_mode(0), BLOCK_MANAGER_SYNC_NONE);
    ASSERT_EQ(convert_sync_mode(1), BLOCK_MANAGER_SYNC_FULL);
    ASSERT_EQ(convert_sync_mode(99), BLOCK_MANAGER_SYNC_NONE);
    ASSERT_EQ(convert_sync_mode(-1), BLOCK_MANAGER_SYNC_NONE);
}

int main(void)
{
    RUN_TEST(test_block_manager_open, tests_passed);
    RUN_TEST(test_block_manager_block_create, tests_passed);
    RUN_TEST(test_block_manager_block_write, tests_passed);
    RUN_TEST(test_block_manager_block_write_batch, tests_passed);
    RUN_TEST(test_block_manager_block_write_close_reopen_read, tests_passed);
    RUN_TEST(test_block_manager_truncate, tests_passed);
    RUN_TEST(test_block_manager_count_blocks, tests_passed);
    RUN_TEST(test_block_manager_cursor_goto_first, tests_passed);
    RUN_TEST(test_block_manager_cursor_has_next, tests_passed);
    RUN_TEST(test_block_manager_cursor_has_prev, tests_passed);
    RUN_TEST(test_block_manager_cursor, tests_passed);
    RUN_TEST(test_block_manager_cursor_goto_last, tests_passed);
    RUN_TEST(test_block_manager_goto_last_after_reopen, tests_passed);
    RUN_TEST(test_block_manager_concurrent_file_extension, tests_passed);
    RUN_TEST(test_block_manager_cursor_position_checks, tests_passed);
    RUN_TEST(test_block_manager_open_safety, tests_passed);
    RUN_TEST(test_block_manager_validate_last_block, tests_passed);
    RUN_TEST(test_block_manager_get_size, tests_passed);
    RUN_TEST(test_block_manager_seek_and_goto, tests_passed);
    RUN_TEST(test_block_manager_validation_edge_cases, tests_passed);
    RUN_TEST(test_block_manager_concurrent_rw, tests_passed);
    RUN_TEST(test_block_manager_sync_modes, tests_passed);
    RUN_TEST(test_block_manager_empty_block, tests_passed);
    RUN_TEST(test_block_manager_concurrent_write_size_reopen, tests_passed);
    RUN_TEST(test_block_manager_block_create_from_buffer, tests_passed);
    RUN_TEST(test_block_manager_write_at_and_update_checksum, tests_passed);
    RUN_TEST(test_block_manager_block_acquire_release, tests_passed);
    RUN_TEST(test_block_manager_cursor_read_partial, tests_passed);
    RUN_TEST(test_block_manager_cursor_read_and_advance, tests_passed);
    RUN_TEST(test_block_manager_escalate_fsync, tests_passed);
    RUN_TEST(test_block_manager_last_modified, tests_passed);
    RUN_TEST(test_block_manager_set_sync_mode, tests_passed);
    RUN_TEST(test_block_manager_get_block_size_at_offset, tests_passed);
    RUN_TEST(test_block_manager_read_at_offset, tests_passed);
    RUN_TEST(test_block_manager_read_block_data_at_offset, tests_passed);
    RUN_TEST(test_block_manager_convert_sync_mode, tests_passed);
    RUN_TEST(test_block_manager_checksum_corruption, tests_passed);
    RUN_TEST(test_block_manager_header_corruption, tests_passed);
    RUN_TEST(test_block_manager_strict_validation, tests_passed);
    RUN_TEST(test_block_manager_validate_zero_size_file, tests_passed);
    RUN_TEST(test_block_manager_footer_corruption_mid_file, tests_passed);

    srand((unsigned int)time(NULL)); /* NOLINT(cert-msc51-cpp) */
    RUN_TEST(benchmark_block_manager, tests_passed);
    RUN_TEST(benchmark_block_manager_iteration, tests_passed);
    RUN_TEST(benchmark_block_manager_parallel_write, tests_passed);

    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
