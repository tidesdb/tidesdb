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
#include "../external/xxhash.h"
#ifndef _WIN32
#include <signal.h>
#include <sys/time.h>
#endif

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

/**
 * test_block_manager_write_raw
 * verifies that block_manager_write_raw produces the same on-disk format
 * as block_manager_block_write, and that blocks written with write_raw
 * are correctly readable via cursor_read after close+reopen.
 */
void test_block_manager_write_raw(void)
{
    /* --- 1. basic write + read back ----------------------------------- */
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, "test_write_raw.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    const char payload[] = "hello_write_raw_test";
    const uint32_t payload_size = (uint32_t)(strlen(payload) + 1);

    int64_t offset = block_manager_write_raw(bm, payload, payload_size);
    ASSERT_TRUE(offset >= 0);

    /* read it back immediately via cursor */
    block_manager_cursor_t *cursor = NULL;
    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);
    ASSERT_TRUE(block_manager_cursor_goto(cursor, (uint64_t)offset) == 0);
    block_manager_block_t *block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(block != NULL);
    ASSERT_EQ(block->size, payload_size);
    ASSERT_EQ(memcmp(block->data, payload, payload_size), 0);
    block_manager_block_free(block);
    block_manager_cursor_free(cursor);

    /* close and reopen to verify persistence */
    ASSERT_TRUE(block_manager_close(bm) == 0);
    ASSERT_TRUE(block_manager_open(&bm, "test_write_raw.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);
    ASSERT_TRUE(block_manager_cursor_goto(cursor, (uint64_t)offset) == 0);
    block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(block != NULL);
    ASSERT_EQ(block->size, payload_size);
    ASSERT_EQ(memcmp(block->data, payload, payload_size), 0);
    block_manager_block_free(block);
    block_manager_cursor_free(cursor);
    ASSERT_TRUE(block_manager_close(bm) == 0);
    remove("test_write_raw.db");

    /* --- 2. multiple raw writes + sequential cursor iteration --------- */
    ASSERT_TRUE(block_manager_open(&bm, "test_write_raw.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    const int num_entries = 20;
    char bufs[20][64];
    for (int i = 0; i < num_entries; i++)
    {
        snprintf(bufs[i], sizeof(bufs[i]), "raw_entry_%04d", i);
        int64_t off = block_manager_write_raw(bm, bufs[i], (uint32_t)(strlen(bufs[i]) + 1));
        ASSERT_TRUE(off >= 0);
    }

    ASSERT_TRUE(block_manager_close(bm) == 0);
    ASSERT_TRUE(block_manager_open(&bm, "test_write_raw.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);
    int count = 0;
    do
    {
        block = block_manager_cursor_read(cursor);
        if (!block) break;
        char expected[64];
        snprintf(expected, sizeof(expected), "raw_entry_%04d", count);
        ASSERT_EQ(strcmp((char *)block->data, expected), 0);
        block_manager_block_free(block);
        count++;
    } while (block_manager_cursor_next(cursor) == 0);

    ASSERT_EQ(count, num_entries);
    block_manager_cursor_free(cursor);
    ASSERT_TRUE(block_manager_close(bm) == 0);
    remove("test_write_raw.db");

    /* --- 3. interleave write_raw and block_write ---------------------- */
    ASSERT_TRUE(block_manager_open(&bm, "test_write_raw.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    const char raw_data[] = "from_write_raw";
    const char blk_data[] = "from_block_write";

    int64_t off_raw = block_manager_write_raw(bm, raw_data, (uint32_t)(strlen(raw_data) + 1));
    ASSERT_TRUE(off_raw >= 0);

    block_manager_block_t *blk = block_manager_block_create(strlen(blk_data) + 1, (void *)blk_data);
    ASSERT_TRUE(blk != NULL);
    int64_t off_blk = block_manager_block_write(bm, blk);
    ASSERT_TRUE(off_blk >= 0);
    block_manager_block_free(blk);

    int64_t off_raw2 = block_manager_write_raw(bm, raw_data, (uint32_t)(strlen(raw_data) + 1));
    ASSERT_TRUE(off_raw2 >= 0);

    ASSERT_TRUE(block_manager_close(bm) == 0);
    ASSERT_TRUE(block_manager_open(&bm, "test_write_raw.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);

    /* block 0-- raw_data */
    block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(block != NULL);
    ASSERT_EQ(strcmp((char *)block->data, raw_data), 0);
    block_manager_block_free(block);

    /* block 1-- blk_data */
    ASSERT_EQ(block_manager_cursor_next(cursor), 0);
    block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(block != NULL);
    ASSERT_EQ(strcmp((char *)block->data, blk_data), 0);
    block_manager_block_free(block);

    /* block 2-- raw_data again */
    ASSERT_EQ(block_manager_cursor_next(cursor), 0);
    block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(block != NULL);
    ASSERT_EQ(strcmp((char *)block->data, raw_data), 0);
    block_manager_block_free(block);

    block_manager_cursor_free(cursor);
    ASSERT_TRUE(block_manager_close(bm) == 0);
    remove("test_write_raw.db");

    /* --- 4. edge cases ------------------------------------------------ */
    ASSERT_TRUE(block_manager_open(&bm, "test_write_raw.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    /* NULL bm, NULL data, zero size should all return -1 */
    ASSERT_EQ(block_manager_write_raw(NULL, raw_data, 10), -1);
    ASSERT_EQ(block_manager_write_raw(bm, NULL, 10), -1);
    ASSERT_EQ(block_manager_write_raw(bm, raw_data, 0), -1);

    /* single-byte payload */
    uint8_t one_byte = 0xAB;
    int64_t off_one = block_manager_write_raw(bm, &one_byte, 1);
    ASSERT_TRUE(off_one >= 0);

    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);
    ASSERT_TRUE(block_manager_cursor_goto(cursor, (uint64_t)off_one) == 0);
    block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(block != NULL);
    ASSERT_TRUE(block->size == 1);
    ASSERT_TRUE(((uint8_t *)block->data)[0] == 0xAB);
    block_manager_block_free(block);
    block_manager_cursor_free(cursor);

    ASSERT_TRUE(block_manager_close(bm) == 0);
    remove("test_write_raw.db");
}

#define NUM_BLOCKS 100000
#define BLOCK_SIZE 256

/**
 * benchmark_block_manager_write_raw
 * compares write throughput of block_manager_write_raw vs block_manager_block_write
 * and verifies data integrity of all blocks written via write_raw.
 */
void benchmark_block_manager_write_raw(void)
{
    const int bench_blocks = NUM_BLOCKS;
    const int bench_size = BLOCK_SIZE;

    /* pre-generate random block data */
    uint8_t **data = malloc(bench_blocks * sizeof(uint8_t *));
    ASSERT_TRUE(data != NULL);
    for (int i = 0; i < bench_blocks; i++)
    {
        data[i] = malloc(bench_size);
        ASSERT_TRUE(data[i] != NULL);
        for (int j = 0; j < bench_size - 20; j++)
        {
            data[i][j] = (uint8_t)(rand() % 256); /* NOLINT(cert-msc30-c,cert-msc50-cpp) */
        }
        snprintf((char *)(data[i] + bench_size - 20), 20, "raw_%d", i);
    }

    /* --- benchmark block_write (baseline) ----------------------------- */
    block_manager_t *bm = NULL;
    (void)remove("bench_raw_baseline.db");
    ASSERT_TRUE(block_manager_open(&bm, "bench_raw_baseline.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    clock_t t0 = clock();
    for (int i = 0; i < bench_blocks; i++)
    {
        block_manager_block_t *blk = block_manager_block_create(bench_size, data[i]);
        ASSERT_TRUE(blk != NULL);
        ASSERT_TRUE(block_manager_block_write(bm, blk) >= 0);
        block_manager_block_free(blk);
    }
    clock_t t1 = clock();
    double baseline_sec = (double)(t1 - t0) / CLOCKS_PER_SEC;

    ASSERT_TRUE(block_manager_close(bm) == 0);
    remove("bench_raw_baseline.db");

    /* --- benchmark write_raw ------------------------------------------ */
    (void)remove("bench_raw_new.db");
    ASSERT_TRUE(block_manager_open(&bm, "bench_raw_new.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    int64_t *offsets = malloc(bench_blocks * sizeof(int64_t));
    ASSERT_TRUE(offsets != NULL);

    t0 = clock();
    for (int i = 0; i < bench_blocks; i++)
    {
        offsets[i] = block_manager_write_raw(bm, data[i], (uint32_t)bench_size);
        ASSERT_TRUE(offsets[i] >= 0);
    }
    t1 = clock();
    double raw_sec = (double)(t1 - t0) / CLOCKS_PER_SEC;

    printf(BOLDWHITE "Benchmark: write_raw vs block_write (%d x %d bytes)\n" RESET, bench_blocks,
           bench_size);
    printf(CYAN "  block_write: %.3f sec (%.2f MB/s)\n", baseline_sec,
           baseline_sec > 0 ? (bench_blocks * bench_size) / (baseline_sec * 1024 * 1024) : 0.0);
    printf("  write_raw:   %.3f sec (%.2f MB/s)\n" RESET, raw_sec,
           raw_sec > 0 ? (bench_blocks * bench_size) / (raw_sec * 1024 * 1024) : 0.0);

    /* --- verify all blocks written by write_raw ----------------------- */
    ASSERT_TRUE(block_manager_close(bm) == 0);
    ASSERT_TRUE(block_manager_open(&bm, "bench_raw_new.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    block_manager_cursor_t *cursor = NULL;
    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);

    int verified = 0;
    do
    {
        block_manager_block_t *block = block_manager_cursor_read(cursor);
        if (!block) break;

        char expected_id[20];
        snprintf(expected_id, sizeof(expected_id), "raw_%d", verified);
        ASSERT_TRUE(
            memcmp((char *)block->data + bench_size - 20, expected_id, strlen(expected_id)) == 0);
        ASSERT_EQ(block->size, (uint64_t)bench_size);

        block_manager_block_free(block);
        verified++;
    } while (block_manager_cursor_next(cursor) == 0);

    ASSERT_EQ(verified, bench_blocks);
    block_manager_cursor_free(cursor);

    ASSERT_TRUE(block_manager_close(bm) == 0);
    remove("bench_raw_new.db");

    free(offsets);
    for (int i = 0; i < bench_blocks; i++) free(data[i]);
    free(data);
}

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

void test_block_manager_null_args(void)
{
    block_manager_t *bm = NULL;

    /* block_manager_open */
    ASSERT_EQ(block_manager_open(NULL, "test.db", BLOCK_MANAGER_SYNC_NONE), -1);
    ASSERT_EQ(block_manager_open(&bm, NULL, BLOCK_MANAGER_SYNC_NONE), -1);

    /* block_manager_close */
    ASSERT_EQ(block_manager_close(NULL), -1);

    /* block_manager_block_create with size > UINT32_MAX */
    block_manager_block_t *block = block_manager_block_create((uint64_t)UINT32_MAX + 1, "data");
    ASSERT_TRUE(block == NULL);

    /* block_manager_block_create_from_buffer with size > UINT32_MAX */
    char *buf = malloc(10);
    block = block_manager_block_create_from_buffer((uint64_t)UINT32_MAX + 1, buf);
    ASSERT_TRUE(block == NULL);
    free(buf);

    /* block_manager_block_write */
    ASSERT_TRUE(block_manager_open(&bm, "test_null.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    block = block_manager_block_create(5, "hello");
    ASSERT_TRUE(block != NULL);
    ASSERT_EQ(block_manager_block_write(NULL, block), -1);
    ASSERT_EQ(block_manager_block_write(bm, NULL), -1);
    block_manager_block_free(block);

    /* block_manager_truncate */
    ASSERT_EQ(block_manager_truncate(NULL), -1);

    /* block_manager_count_blocks */
    ASSERT_EQ(block_manager_count_blocks(NULL), -1);

    /* block_manager_get_size */
    uint64_t size;
    ASSERT_EQ(block_manager_get_size(NULL, &size), -1);
    ASSERT_EQ(block_manager_get_size(bm, NULL), -1);

    /* block_manager_get_block_size_at_offset */
    uint32_t bsize;
    ASSERT_EQ(block_manager_get_block_size_at_offset(NULL, 0, &bsize), -1);
    ASSERT_EQ(block_manager_get_block_size_at_offset(bm, 0, NULL), -1);

    /* block_manager_read_at_offset */
    uint8_t rbuf[10];
    ASSERT_EQ(block_manager_read_at_offset(NULL, 0, 10, rbuf), -1);
    ASSERT_EQ(block_manager_read_at_offset(bm, 0, 0, rbuf), -1);
    ASSERT_EQ(block_manager_read_at_offset(bm, 0, 10, NULL), -1);

    /* block_manager_read_block_data_at_offset */
    uint8_t *out_data = NULL;
    uint32_t out_size = 0;
    ASSERT_EQ(block_manager_read_block_data_at_offset(NULL, 0, &out_data, &out_size), -1);
    ASSERT_EQ(block_manager_read_block_data_at_offset(bm, 0, NULL, &out_size), -1);
    ASSERT_EQ(block_manager_read_block_data_at_offset(bm, 0, &out_data, NULL), -1);

    /* block_manager_update_checksum */
    ASSERT_EQ(block_manager_update_checksum(NULL, 0), -1);
    ASSERT_EQ(block_manager_update_checksum(bm, -1), -1);

    /* block_manager_write_at */
    uint8_t wbuf[4] = {0};
    ASSERT_EQ(block_manager_write_at(NULL, 0, wbuf, 4), -1);
    ASSERT_EQ(block_manager_write_at(bm, 0, NULL, 4), -1);
    ASSERT_EQ(block_manager_write_at(bm, 0, wbuf, 0), -1);
    ASSERT_EQ(block_manager_write_at(bm, -1, wbuf, 4), -1);

    /* block_manager_escalate_fsync(NULL) already tested, skip */

    /* block_manager_last_modified(NULL) already tested, skip */

    /* cursor functions */
    block_manager_cursor_t *cursor = NULL;
    ASSERT_EQ(block_manager_cursor_init(&cursor, NULL), -1);
    ASSERT_EQ(block_manager_cursor_init_stack(NULL, bm), -1);

    block_manager_cursor_t stack_cursor;
    ASSERT_EQ(block_manager_cursor_init_stack(&stack_cursor, NULL), -1);

    ASSERT_EQ(block_manager_cursor_next(NULL), -1);
    ASSERT_EQ(block_manager_cursor_prev(NULL), -1);
    ASSERT_EQ(block_manager_cursor_goto(NULL, 0), -1);
    ASSERT_EQ(block_manager_cursor_goto_first(NULL), -1);
    ASSERT_EQ(block_manager_cursor_goto_last(NULL), -1);
    ASSERT_EQ(block_manager_cursor_has_next(NULL), -1);
    ASSERT_EQ(block_manager_cursor_has_prev(NULL), -1);
    ASSERT_EQ(block_manager_cursor_at_first(NULL), -1);
    ASSERT_EQ(block_manager_cursor_at_second(NULL), -1);
    ASSERT_EQ(block_manager_cursor_at_last(NULL), -1);
    ASSERT_TRUE(block_manager_cursor_read(NULL) == NULL);
    ASSERT_TRUE(block_manager_cursor_read_partial(NULL, 10) == NULL);
    ASSERT_TRUE(block_manager_cursor_read_and_advance(NULL) == NULL);

    /* block_manager_block_free and cursor_free with NULL should not crash */
    block_manager_block_free(NULL);
    block_manager_cursor_free(NULL);
    block_manager_block_release(NULL);

    ASSERT_TRUE(block_manager_close(bm) == 0);
    remove("test_null.db");
}

void test_block_manager_cursor_has_next_exhausted(void)
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, "test_has_next_end.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    for (int i = 0; i < 2; i++)
    {
        char data[10];
        snprintf(data, 10, "testdata%d", i);
        block_manager_block_t *block = block_manager_block_create(10, data);
        ASSERT_TRUE(block != NULL);
        ASSERT_TRUE(block_manager_block_write(bm, block) >= 0);
        block_manager_block_free(block);
    }

    block_manager_cursor_t *cursor;
    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);

    /* at first block, has_next should be 1 */
    ASSERT_EQ(block_manager_cursor_has_next(cursor), 1);
    ASSERT_EQ(block_manager_cursor_next(cursor), 0);

    /* at second (last) block, has_next should still be 1 (current block is valid) */
    ASSERT_EQ(block_manager_cursor_has_next(cursor), 1);

    /* advance past the last block */
    ASSERT_EQ(block_manager_cursor_next(cursor), 0);

    /* now past all blocks, has_next should return 0 */
    ASSERT_EQ(block_manager_cursor_has_next(cursor), 0);

    block_manager_cursor_free(cursor);
    ASSERT_TRUE(block_manager_close(bm) == 0);
    remove("test_has_next_end.db");
}

void test_block_manager_cursor_next_past_eof(void)
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, "test_next_eof.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    char data[10] = "one_block";
    block_manager_block_t *block = block_manager_block_create(10, data);
    ASSERT_TRUE(block != NULL);
    ASSERT_TRUE(block_manager_block_write(bm, block) >= 0);
    block_manager_block_free(block);

    block_manager_cursor_t *cursor;
    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);

    /* advance past the single block */
    ASSERT_EQ(block_manager_cursor_next(cursor), 0);

    /* cursor_next should now fail (EOF) */
    ASSERT_NE(block_manager_cursor_next(cursor), 0);

    /* cursor_read at this position should return NULL */
    ASSERT_TRUE(block_manager_cursor_read(cursor) == NULL);

    block_manager_cursor_free(cursor);
    ASSERT_TRUE(block_manager_close(bm) == 0);
    remove("test_next_eof.db");
}

void test_block_manager_count_blocks_large_block(void)
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, "test_large_count.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    /* write a block larger than the 64KB count buffer to exercise the off==0 path */
    const size_t large_size = 128 * 1024;
    uint8_t *large_data = malloc(large_size);
    ASSERT_TRUE(large_data != NULL);
    memset(large_data, 'X', large_size);

    block_manager_block_t *block = block_manager_block_create(large_size, large_data);
    ASSERT_TRUE(block != NULL);
    ASSERT_TRUE(block_manager_block_write(bm, block) >= 0);
    block_manager_block_free(block);

    /* write a small block after it */
    block = block_manager_block_create(5, "small");
    ASSERT_TRUE(block != NULL);
    ASSERT_TRUE(block_manager_block_write(bm, block) >= 0);
    block_manager_block_free(block);

    ASSERT_EQ(block_manager_count_blocks(bm), 2);

    /* verify on empty file (header only) */
    ASSERT_TRUE(block_manager_close(bm) == 0);
    ASSERT_TRUE(block_manager_open(&bm, "test_empty_count.db", BLOCK_MANAGER_SYNC_NONE) == 0);
    ASSERT_EQ(block_manager_count_blocks(bm), 0);

    ASSERT_TRUE(block_manager_close(bm) == 0);
    free(large_data);
    remove("test_large_count.db");
    remove("test_empty_count.db");
}

void test_block_manager_cursor_goto_invalid(void)
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, "test_goto_invalid.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    char data[10] = "testdata0";
    block_manager_block_t *block = block_manager_block_create(10, data);
    ASSERT_TRUE(block != NULL);
    ASSERT_TRUE(block_manager_block_write(bm, block) >= 0);
    block_manager_block_free(block);

    block_manager_cursor_t *cursor;
    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);

    /* goto position 0 (inside file header), cursor_read should fail */
    ASSERT_EQ(block_manager_cursor_goto(cursor, 0), 0);
    block_manager_block_t *read_block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(read_block == NULL);

    /* goto position way beyond file size, cursor_read should fail */
    ASSERT_EQ(block_manager_cursor_goto(cursor, 999999), 0);
    read_block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(read_block == NULL);

    /* goto_last on empty file should fail */
    block_manager_cursor_free(cursor);
    ASSERT_TRUE(block_manager_close(bm) == 0);

    ASSERT_TRUE(block_manager_open(&bm, "test_goto_empty.db", BLOCK_MANAGER_SYNC_NONE) == 0);
    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);
    ASSERT_EQ(block_manager_cursor_goto_last(cursor), -1);

    block_manager_cursor_free(cursor);
    ASSERT_TRUE(block_manager_close(bm) == 0);
    remove("test_goto_invalid.db");
    remove("test_goto_empty.db");
}

void test_block_manager_read_block_data_checksum_corruption(void)
{
    block_manager_t *bm = NULL;
    (void)remove("test_rbd_cksum.db");
    ASSERT_TRUE(block_manager_open(&bm, "test_rbd_cksum.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    block_manager_block_t *block = block_manager_block_create(10, "integrityX");
    ASSERT_TRUE(block != NULL);
    int64_t offset = block_manager_block_write(bm, block);
    ASSERT_TRUE(offset >= 0);
    block_manager_block_free(block);
    block_manager_escalate_fsync(bm);

    /* corrupt the checksum field */
    uint8_t bad_cksum[4] = {0xFF, 0xFF, 0xFF, 0xFF};
    int64_t cksum_offset = offset + BLOCK_MANAGER_SIZE_FIELD_SIZE;
    ASSERT_EQ(block_manager_write_at(bm, cksum_offset, bad_cksum, 4), 0);

    /* read_block_data_at_offset should fail due to checksum mismatch */
    uint8_t *out_data = NULL;
    uint32_t out_size = 0;
    ASSERT_EQ(block_manager_read_block_data_at_offset(bm, (uint64_t)offset, &out_data, &out_size),
              -1);
    ASSERT_TRUE(out_data == NULL);

    ASSERT_TRUE(block_manager_close(bm) == 0);
    remove("test_rbd_cksum.db");
}

void test_block_manager_cursor_init_stack_direct(void)
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, "test_stack_cursor.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    for (int i = 0; i < 3; i++)
    {
        char data[10];
        snprintf(data, 10, "testdata%d", i);
        block_manager_block_t *block = block_manager_block_create(10, data);
        ASSERT_TRUE(block != NULL);
        ASSERT_TRUE(block_manager_block_write(bm, block) >= 0);
        block_manager_block_free(block);
    }

    /* use stack-allocated cursor */
    block_manager_cursor_t cursor;
    ASSERT_EQ(block_manager_cursor_init_stack(&cursor, bm), 0);

    /* should be positioned at first block */
    block_manager_block_t *read_block = block_manager_cursor_read(&cursor);
    ASSERT_TRUE(read_block != NULL);
    ASSERT_EQ(memcmp(read_block->data, "testdata0", 10), 0);
    block_manager_block_free(read_block);

    /* iterate forward */
    ASSERT_EQ(block_manager_cursor_next(&cursor), 0);
    read_block = block_manager_cursor_read(&cursor);
    ASSERT_TRUE(read_block != NULL);
    ASSERT_EQ(memcmp(read_block->data, "testdata1", 10), 0);
    block_manager_block_free(read_block);

    ASSERT_EQ(block_manager_cursor_next(&cursor), 0);
    read_block = block_manager_cursor_read(&cursor);
    ASSERT_TRUE(read_block != NULL);
    ASSERT_EQ(memcmp(read_block->data, "testdata2", 10), 0);
    block_manager_block_free(read_block);

    /* no cursor_free needed for stack cursor */
    ASSERT_TRUE(block_manager_close(bm) == 0);
    remove("test_stack_cursor.db");
}

void test_block_manager_write_batch_edge_cases(void)
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, "test_batch_edge.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    /* NULL offsets array should return -1 */
    block_manager_block_t *block = block_manager_block_create(5, "hello");
    ASSERT_TRUE(block != NULL);
    ASSERT_EQ(block_manager_block_write_batch(bm, &block, 1, NULL), -1);
    block_manager_block_free(block);

    /* count=0 should return -1 */
    int64_t offsets[4];
    block_manager_block_t *blocks[4];
    ASSERT_EQ(block_manager_block_write_batch(bm, blocks, 0, offsets), -1);

    /* batch with NULL blocks interspersed */
    blocks[0] = block_manager_block_create(6, "first_");
    blocks[1] = NULL;
    blocks[2] = block_manager_block_create(7, "third__");
    blocks[3] = NULL;
    ASSERT_TRUE(blocks[0] != NULL);
    ASSERT_TRUE(blocks[2] != NULL);

    int result = block_manager_block_write_batch(bm, blocks, 4, offsets);
    ASSERT_EQ(result, 2);

    /* valid blocks should have valid offsets */
    ASSERT_TRUE(offsets[0] >= 0);
    ASSERT_TRUE(offsets[2] >= 0);

    /* NULL blocks should have offset -1 */
    ASSERT_EQ(offsets[1], -1);
    ASSERT_EQ(offsets[3], -1);

    block_manager_block_free(blocks[0]);
    block_manager_block_free(blocks[2]);

    /* verify the 2 written blocks are readable */
    ASSERT_TRUE(block_manager_close(bm) == 0);
    ASSERT_TRUE(block_manager_open(&bm, "test_batch_edge.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    block_manager_cursor_t *cursor;
    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);

    block_manager_block_t *read_block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(read_block != NULL);
    ASSERT_EQ(memcmp(read_block->data, "first_", 6), 0);
    block_manager_block_free(read_block);

    ASSERT_EQ(block_manager_cursor_next(cursor), 0);
    read_block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(read_block != NULL);
    ASSERT_EQ(memcmp(read_block->data, "third__", 7), 0);
    block_manager_block_free(read_block);

    block_manager_cursor_free(cursor);
    ASSERT_TRUE(block_manager_close(bm) == 0);
    remove("test_batch_edge.db");
}

void test_block_manager_cursor_read_partial_large_max(void)
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, "test_partial_large.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    char data[50];
    memset(data, 'B', 50);
    block_manager_block_t *block = block_manager_block_create(50, data);
    ASSERT_TRUE(block != NULL);
    ASSERT_TRUE(block_manager_block_write(bm, block) >= 0);
    block_manager_block_free(block);

    block_manager_cursor_t *cursor;
    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);

    /* max_bytes >= block_size should return full block */
    block_manager_block_t *partial = block_manager_cursor_read_partial(cursor, 50);
    ASSERT_TRUE(partial != NULL);
    ASSERT_EQ(partial->size, 50);
    block_manager_block_free(partial);

    partial = block_manager_cursor_read_partial(cursor, 1000);
    ASSERT_TRUE(partial != NULL);
    ASSERT_EQ(partial->size, 50);
    block_manager_block_free(partial);

    block_manager_cursor_free(cursor);
    ASSERT_TRUE(block_manager_close(bm) == 0);
    remove("test_partial_large.db");
}

void test_write_raw_hole_stops_replay(void)
{
    const char *test_file = "test_hole_stops_replay.db";
    (void)remove(test_file);

    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, test_file, BLOCK_MANAGER_SYNC_NONE) == 0);

    const char *payload_a  = "block_A_payload";
    const uint32_t size_a  = (uint32_t)(strlen(payload_a) + 1);
    int64_t offset_a       = block_manager_write_raw(bm, payload_a, size_a);
    ASSERT_TRUE(offset_a >= 0);

    const char *payload_b  = "block_B_payload";
    const uint32_t size_b  = (uint32_t)(strlen(payload_b) + 1);
    int64_t offset_b       = block_manager_write_raw(bm, payload_b, size_b);
    ASSERT_TRUE(offset_b >= 0);

    const char *payload_c  = "block_C_payload";
    const uint32_t size_c  = (uint32_t)(strlen(payload_c) + 1);
    int64_t offset_c       = block_manager_write_raw(bm, payload_c, size_c);
    ASSERT_TRUE(offset_c >= 0);

    /*
     * Simulate pwritev failure on block B by zeroing its entire reserved
     * region.  On Linux the kernel fills unwritten regions with zeros when a
     * file is extended via lseek/ftruncate; pwritev failure after the file
     * counter was advanced leaves the same zero-filled gap.
     */
    const size_t b_total = BLOCK_MANAGER_BLOCK_HEADER_SIZE + size_b + BLOCK_MANAGER_FOOTER_SIZE;
    uint8_t *zeros = (uint8_t *)calloc(1, b_total);
    ASSERT_TRUE(zeros != NULL);
    ASSERT_TRUE(pwrite(bm->fd, zeros, b_total, (off_t)offset_b) == (ssize_t)b_total);
    free(zeros);

    /* close and reopen to model the crash-recovery / WAL-replay scenario */
    ASSERT_TRUE(block_manager_close(bm) == 0);
    ASSERT_TRUE(block_manager_open(&bm, test_file, BLOCK_MANAGER_SYNC_NONE) == 0);

    block_manager_cursor_t *cursor = NULL;
    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);

    /* block A is readable via sequential scan */
    block_manager_block_t *block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(block != NULL);
    ASSERT_EQ(memcmp(block->data, payload_a, size_a), 0);
    block_manager_block_free(block);

    /*
     * cursor_next from A uses A's cached size to advance the file pointer to
     * block B's offset.  It does NOT read B's content here, it just moves
     * the cursor position.  Therefore it returns 0 (success).
     */
    ASSERT_EQ(block_manager_cursor_next(cursor), 0);

    /*
     * cursor_read at B's offset now reads the size field: 0x00000000.
     * block_manager_read_block_at_offset treats size=0 as invalid and returns
     * NULL.  This is the point where WAL replay must stop since it cannot
     * distinguish the hole from a genuine write boundary.
     */
    block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(block == NULL);

    /*
     * cursor_next from the same (hole) position reads B's size field again
     * (cache was invalidated since cursor_read returned NULL).  size=0 makes
     * cursor_next return -1, confirming the cursor is permanently stuck.
     */
    ASSERT_EQ(block_manager_cursor_next(cursor), -1);

    /*
     * Prove block C is durably on disk despite being unreachable via sequential
     * scan.  cursor_goto jumps directly to its known offset and reads it fine.
     * This confirms the data loss is caused entirely by the hole, not by C
     * having been corrupted.
     */
    ASSERT_TRUE(block_manager_cursor_goto(cursor, (uint64_t)offset_c) == 0);
    block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(block != NULL);
    ASSERT_EQ(memcmp(block->data, payload_c, size_c), 0);
    block_manager_block_free(block);

    printf("  [hole-stops-replay] block C at offset %" PRId64
           " is on disk but unreachable from sequential scan\n",
           offset_c);

    block_manager_cursor_free(cursor);
    ASSERT_TRUE(block_manager_close(bm) == 0);
    (void)remove(test_file);
}

/**
 * test_write_raw_multiple_holes_stop_replay
 *
 * Extends the single-hole test: two consecutive failed pwritev calls leave
 * two zero-filled holes.  Replay stops at the first hole, compounding data
 * loss for every block written after it.
 *
 * File layout:  [A (valid)] [hole B] [hole D] [E (valid)]
 * Expected:     cursor reads A, cursor_next returns -1 at hole B, E is lost.
 */
void test_write_raw_multiple_holes_stop_replay(void)
{
    const char *test_file = "test_multi_hole.db";
    (void)remove(test_file);

    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, test_file, BLOCK_MANAGER_SYNC_NONE) == 0);

    const char *payload_a = "block_A";
    const char *payload_b = "block_B_will_become_hole";
    const char *payload_d = "block_D_will_become_hole";
    const char *payload_e = "block_E_valid";

    const uint32_t size_a = (uint32_t)(strlen(payload_a) + 1);
    const uint32_t size_b = (uint32_t)(strlen(payload_b) + 1);
    const uint32_t size_d = (uint32_t)(strlen(payload_d) + 1);
    const uint32_t size_e = (uint32_t)(strlen(payload_e) + 1);

    int64_t offset_a = block_manager_write_raw(bm, payload_a, size_a);
    int64_t offset_b = block_manager_write_raw(bm, payload_b, size_b);
    int64_t offset_d = block_manager_write_raw(bm, payload_d, size_d);
    int64_t offset_e = block_manager_write_raw(bm, payload_e, size_e);

    ASSERT_TRUE(offset_a >= 0);
    ASSERT_TRUE(offset_b >= 0);
    ASSERT_TRUE(offset_d >= 0);
    ASSERT_TRUE(offset_e >= 0);

    const size_t b_total = BLOCK_MANAGER_BLOCK_HEADER_SIZE + size_b + BLOCK_MANAGER_FOOTER_SIZE;
    const size_t d_total = BLOCK_MANAGER_BLOCK_HEADER_SIZE + size_d + BLOCK_MANAGER_FOOTER_SIZE;

    uint8_t *zeros_b = (uint8_t *)calloc(1, b_total);
    uint8_t *zeros_d = (uint8_t *)calloc(1, d_total);
    ASSERT_TRUE(zeros_b != NULL);
    ASSERT_TRUE(zeros_d != NULL);

    ASSERT_TRUE(pwrite(bm->fd, zeros_b, b_total, (off_t)offset_b) == (ssize_t)b_total);
    ASSERT_TRUE(pwrite(bm->fd, zeros_d, d_total, (off_t)offset_d) == (ssize_t)d_total);

    free(zeros_b);
    free(zeros_d);

    ASSERT_TRUE(block_manager_close(bm) == 0);
    ASSERT_TRUE(block_manager_open(&bm, test_file, BLOCK_MANAGER_SYNC_NONE) == 0);

    block_manager_cursor_t *cursor = NULL;
    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);

    /* block A is readable */
    block_manager_block_t *block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(block != NULL);
    ASSERT_EQ(memcmp(block->data, payload_a, size_a), 0);
    block_manager_block_free(block);

    ASSERT_EQ(block_manager_cursor_next(cursor), 0);

    block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(block == NULL);

    /* cursor_next from the hole confirms the cursor is stuck */
    ASSERT_EQ(block_manager_cursor_next(cursor), -1);

    /* block E is durably on disk but completely unreachable via sequential scan */
    ASSERT_TRUE(block_manager_cursor_goto(cursor, (uint64_t)offset_e) == 0);
    block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(block != NULL);
    ASSERT_EQ(memcmp(block->data, payload_e, size_e), 0);
    block_manager_block_free(block);

    printf("  [multi-hole] replay stopped at first hole; block E at offset %" PRId64
           " is unreachable\n",
           offset_e);

    block_manager_cursor_free(cursor);
    ASSERT_TRUE(block_manager_close(bm) == 0);
    (void)remove(test_file);
}

#ifndef _WIN32
static volatile int g_signal_count = 0;

static void test_sigalrm_handler(int signum)
{
    (void)signum;
    g_signal_count++;
}

void test_block_manager_write_raw_signal_safe(void)
{
    const char *test_file = "test_signal_safe.db";
    (void)remove(test_file);

    /* install non-SA_RESTART SIGALRM handler so EINTR would be visible */
    struct sigaction sa, old_sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = test_sigalrm_handler;
    sa.sa_flags   = 0;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGALRM, &sa, &old_sa);

    struct itimerval itv;
    itv.it_interval.tv_sec  = 0;
    itv.it_interval.tv_usec = 500;
    itv.it_value.tv_sec     = 0;
    itv.it_value.tv_usec    = 500;
    setitimer(ITIMER_REAL, &itv, NULL);

    g_signal_count = 0;

    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, test_file, BLOCK_MANAGER_SYNC_NONE) == 0);

    const char *payload = "signal_safe_test_block_payload_data";
    const uint32_t size = (uint32_t)(strlen(payload) + 1);
    int failures = 0;

    for (int i = 0; i < 1000; i++)
    {
        if (block_manager_write_raw(bm, payload, size) < 0) failures++;
    }

    /* disarm timer and restore original handler before assertions */
    memset(&itv, 0, sizeof(itv));
    setitimer(ITIMER_REAL, &itv, NULL);
    sigaction(SIGALRM, &old_sa, NULL);

    ASSERT_EQ(failures, 0);
    ASSERT_TRUE(g_signal_count > 0);
    printf("  [signal-safe] %d signals delivered, 0/%d write failures\n",
           g_signal_count, 1000);

    ASSERT_TRUE(block_manager_close(bm) == 0);
    (void)remove(test_file);
}
#endif /* !_WIN32 */

void test_cursor_skip_corrupt_partial_write(void)
{
    const char *test_file = "test_skip_corrupt_partial.db";
    (void)remove(test_file);

    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, test_file, BLOCK_MANAGER_SYNC_NONE) == 0);

    const char *payload_a = "block_A_ok";
    const char *payload_b = "block_B_partial_write_victim";
    const char *payload_c = "block_C_ok";

    const uint32_t size_a = (uint32_t)(strlen(payload_a) + 1);
    const uint32_t size_b = (uint32_t)(strlen(payload_b) + 1);
    const uint32_t size_c = (uint32_t)(strlen(payload_c) + 1);

    const int64_t offset_a = block_manager_write_raw(bm, payload_a, size_a);
    const int64_t offset_b = block_manager_write_raw(bm, payload_b, size_b);
    const int64_t offset_c = block_manager_write_raw(bm, payload_c, size_c);
    ASSERT_TRUE(offset_a >= 0);
    ASSERT_TRUE(offset_b >= 0);
    ASSERT_TRUE(offset_c >= 0);

    /* simulate partial write at B: leave header intact, zero data+footer.
     * the header's size field stays valid (size_b); the footer magic becomes 0. */
    const size_t zero_len = size_b + BLOCK_MANAGER_FOOTER_SIZE;
    uint8_t *zeros = (uint8_t *)calloc(1, zero_len);
    ASSERT_TRUE(zeros != NULL);
    const off_t data_start = (off_t)offset_b + BLOCK_MANAGER_BLOCK_HEADER_SIZE;
    ASSERT_TRUE(pwrite(bm->fd, zeros, zero_len, data_start) == (ssize_t)zero_len);
    free(zeros);

    ASSERT_TRUE(block_manager_close(bm) == 0);
    ASSERT_TRUE(block_manager_open(&bm, test_file, BLOCK_MANAGER_SYNC_NONE) == 0);

    block_manager_cursor_t *cursor = NULL;
    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);

    block_manager_block_t *block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(block != NULL);
    ASSERT_EQ(memcmp(block->data, payload_a, size_a), 0);
    block_manager_block_free(block);

    ASSERT_EQ(block_manager_cursor_next(cursor), 0);

    /* cursor_read(B) must fail: checksum mismatch on zeroed data */
    block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(block == NULL);

    /* skip the partial write -- must succeed because footer magic is absent */
    ASSERT_EQ(block_manager_cursor_skip_corrupt(cursor), 0);

    /* C is now current and readable */
    block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(block != NULL);
    ASSERT_EQ(memcmp(block->data, payload_c, size_c), 0);
    block_manager_block_free(block);

    printf("  [skip-corrupt] block C at offset %" PRId64
           " recovered after skipping partial write at offset %" PRId64 "\n",
           offset_c, offset_b);

    block_manager_cursor_free(cursor);
    ASSERT_TRUE(block_manager_close(bm) == 0);
    (void)remove(test_file);
}

void test_cursor_skip_corrupt_refuses_data_corruption(void)
{
    const char *test_file = "test_skip_corrupt_genuine.db";
    (void)remove(test_file);

    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, test_file, BLOCK_MANAGER_SYNC_NONE) == 0);

    const char *payload = "fully_written_then_bit_flipped";
    const uint32_t size = (uint32_t)(strlen(payload) + 1);

    const int64_t offset = block_manager_write_raw(bm, payload, size);
    ASSERT_TRUE(offset >= 0);

    /* flip one byte in the middle of the data region */
    const off_t flip_offset = (off_t)offset + BLOCK_MANAGER_BLOCK_HEADER_SIZE + (off_t)(size / 2);
    uint8_t byte_val;
    ASSERT_TRUE(pread(bm->fd, &byte_val, 1, flip_offset) == 1);
    byte_val ^= 0xFFU;
    ASSERT_TRUE(pwrite(bm->fd, &byte_val, 1, flip_offset) == 1);

    ASSERT_TRUE(block_manager_close(bm) == 0);
    ASSERT_TRUE(block_manager_open(&bm, test_file, BLOCK_MANAGER_SYNC_NONE) == 0);

    block_manager_cursor_t *cursor = NULL;
    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);

    /* cursor_read must fail: checksum mismatch */
    block_manager_block_t *block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(block == NULL);

    /* skip must be refused: footer magic is intact -> genuine corruption */
    ASSERT_EQ(block_manager_cursor_skip_corrupt(cursor), -1);

    printf("  [skip-corrupt] correctly refused to skip genuine corruption at offset %" PRId64 "\n",
           offset);

    block_manager_cursor_free(cursor);
    ASSERT_TRUE(block_manager_close(bm) == 0);
    (void)remove(test_file);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_block_manager_open, tests_passed);
    RUN_TEST(test_block_manager_block_create, tests_passed);
    RUN_TEST(test_block_manager_block_write, tests_passed);
    RUN_TEST(test_block_manager_block_write_batch, tests_passed);
    RUN_TEST(test_block_manager_write_raw, tests_passed);
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
    RUN_TEST(test_block_manager_null_args, tests_passed);
    RUN_TEST(test_block_manager_cursor_has_next_exhausted, tests_passed);
    RUN_TEST(test_block_manager_cursor_next_past_eof, tests_passed);
    RUN_TEST(test_block_manager_count_blocks_large_block, tests_passed);
    RUN_TEST(test_block_manager_cursor_goto_invalid, tests_passed);
    RUN_TEST(test_block_manager_read_block_data_checksum_corruption, tests_passed);
    RUN_TEST(test_block_manager_cursor_init_stack_direct, tests_passed);
    RUN_TEST(test_block_manager_write_batch_edge_cases, tests_passed);
    RUN_TEST(test_block_manager_cursor_read_partial_large_max, tests_passed);
    RUN_TEST(test_write_raw_hole_stops_replay, tests_passed);
    RUN_TEST(test_write_raw_multiple_holes_stop_replay, tests_passed);

#ifndef _WIN32
    RUN_TEST(test_block_manager_write_raw_signal_safe, tests_passed);
#endif
    RUN_TEST(test_cursor_skip_corrupt_partial_write, tests_passed);
    RUN_TEST(test_cursor_skip_corrupt_refuses_data_corruption, tests_passed);

    srand((unsigned int)time(NULL)); /* NOLINT(cert-msc51-cpp) */
    RUN_TEST(benchmark_block_manager, tests_passed);
    RUN_TEST(benchmark_block_manager_write_raw, tests_passed);
    RUN_TEST(benchmark_block_manager_iteration, tests_passed);
    RUN_TEST(benchmark_block_manager_parallel_write, tests_passed);

    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
