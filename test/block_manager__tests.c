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
#include <assert.h>

#include "../src/block_manager.h"
#include "test_macros.h"

void test_block_manager_open()
{
    block_manager_t *bm;
    assert(block_manager_open(&bm, "test.db", 10000) == 0);
    assert(bm != NULL);
    assert(bm->file != NULL);
    assert(strcmp(bm->file_path, "test.db") == 0);
    assert(bm->fsync_interval == 10000);
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
    assert(block != NULL);
    assert(block->size == size);

    /* we verify that the data is copied correctly */
    assert(memcmp(block->data, data, size) == 0);
    (void)block_manager_block_free(block);

    printf(GREEN "test_block_manager_block_create passed\n" RESET);
}

void test_block_manager_block_write()
{
    /* we set up a new block manager */
    block_manager_t *bm;
    if (block_manager_open(&bm, "test.db", 10000) != 0) return;

    /* we set up a new block */
    uint64_t size = 10;
    char data[10] = "testdata";
    block_manager_block_t *block = block_manager_block_create(size, data);
    assert(block != NULL); /* we verify that the block was created successfully */

    /* now we write the block to the file */
    assert(block_manager_block_write(bm, block, 1) == 0);

    (void)block_manager_block_free(block);

    /* we close the block manager */
    assert(block_manager_close(bm) == 0);

    /* we remove the file */
    (void)remove("test.db");

    printf(GREEN "test_block_manager_block_write passed\n" RESET);
}

void test_block_manager_block_write_close_reopen_read()
{
    /* we set up a new block manager */
    block_manager_t *bm;
    if (block_manager_open(&bm, "test.db", 10000) != 0) return;

    /* we set up a new block */
    uint64_t size = 10;
    char data[10] = "testdata";
    block_manager_block_t *block = block_manager_block_create(size, data);
    assert(block != NULL); /* we verify that the block was created successfully */

    /* now we write the block to the file */
    assert(block_manager_block_write(bm, block, 1) == 0);

    (void)block_manager_block_free(block);

    /* we close the block manager */
    assert(block_manager_close(bm) == 0);

    /* we reopen the block manager */
    if (block_manager_open(&bm, "test.db", 10000) != 0) return;

    /* we read the block from the file */
    block = block_manager_block_read(bm);
    assert(block != NULL);

    /* we verify that the block was read correctly */
    assert(block->size == size);
    assert(memcmp(block->data, data, size) == 0);

    (void)block_manager_block_free(block);

    /* we close the block manager */
    assert(block_manager_close(bm) == 0);

    /* we remove the file */
    remove("test.db");

    printf(GREEN "test_block_manager_block_write_close_reopen_read passed\n" RESET);
}

void test_block_manager_truncate()
{
    /* we set up a new block manager */
    block_manager_t *bm;
    if (block_manager_open(&bm, "test.db", 10000) != 0) return;

    /* we set up a new block */
    uint64_t size = 10;
    char data[10] = "testdata";
    block_manager_block_t *block = block_manager_block_create(size, data);
    assert(block != NULL); /* we verify that the block was created successfully */

    /* now we write the block to the file */
    assert(block_manager_block_write(bm, block, 1) == 0);

    (void)block_manager_block_free(block);

    /* we truncate the file */
    assert(block_manager_truncate(bm) == 0);

    /* we close the block manager */
    assert(block_manager_close(bm) == 0);

    /* we reopen the block manager */
    if (block_manager_open(&bm, "test.db", 10000) != 0) return;

    /* we read the block from the file */
    block = block_manager_block_read(bm);
    assert(block == NULL); /* we expect the block to be NULL */

    /* we close the block manager */
    assert(block_manager_close(bm) == 0);

    /* we remove the file */
    (void)remove("test.db");

    printf(GREEN "test_block_manager_truncate passed\n" RESET);
}

void test_block_manager_cursor()
{
    /* we create a block manager, write a few blocks and verify forward and backward iteration */

    /* we set up a new block manager */
    block_manager_t *bm;
    if (block_manager_open(&bm, "test.db", 10000) != 0) return;

    for (int i = 0; i < 3; i++)
    {
        /* we set up a new block */
        uint64_t size = 10;
        char data[10];

        snprintf(data, 10, "testdata%d", i);

        block_manager_block_t *block = block_manager_block_create(size, data);
        assert(block != NULL); /* we verify that the block was created successfully */

        /* now we write the block to the file */
        /* should not be -1 */
        assert(block_manager_block_write(bm, block, 1) != -1);

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
    assert(read_block->size == 10);
    assert(memcmp(read_block->data, "testdata0", 10) == 0);

    (void)block_manager_block_free(read_block);

    /* we go next */
    assert(block_manager_cursor_next(cursor) == 0);

    /* check next block */
    read_block = block_manager_cursor_read(cursor);
    if (read_block == NULL)
    {
        (void)block_manager_cursor_free(cursor);
        (void)block_manager_close(bm);
        return;
    }

    assert(read_block->size == 10);
    assert(memcmp(read_block->data, "testdata1", 10) == 0);

    (void)block_manager_block_free(read_block);

    /* we go next */
    assert(block_manager_cursor_next(cursor) == 0);

    /* check next block */
    read_block = block_manager_cursor_read(cursor);
    if (read_block == NULL)
    {
        (void)block_manager_cursor_free(cursor);
        (void)block_manager_close(bm);
        return;
    }

    /* we verify that the block was read correctly */
    assert(read_block->size == 10);
    assert(memcmp(read_block->data, "testdata2", 10) == 0);

    (void)block_manager_block_free(read_block);

    /* we go back */
    assert(block_manager_cursor_prev(cursor) == 0);

    /* check previous block */
    read_block = block_manager_cursor_read(cursor);
    if (read_block == NULL)
    {
        (void)block_manager_cursor_free(cursor);
        (void)block_manager_close(bm);
        return;
    }

    /* we verify that the block was read correctly */
    assert(read_block->size == 10);
    assert(memcmp(read_block->data, "testdata1", 10) == 0);

    (void)block_manager_block_free(read_block);

    /* we go back */
    assert(block_manager_cursor_prev(cursor) == 0);

    /* check previous block */
    read_block = block_manager_cursor_read(cursor);
    if (read_block == NULL)
    {
        (void)block_manager_cursor_free(cursor);
        (void)block_manager_close(bm);
        return;
    }

    /* we verify that the block was read correctly */
    assert(read_block->size == 10);
    assert(memcmp(read_block->data, "testdata0", 10) == 0);

    (void)block_manager_block_free(read_block);

    /* we free the cursor */
    (void)block_manager_cursor_free(cursor);

    /* we close the block manager */
    assert(block_manager_close(bm) == 0);

    /* we remove the file */
    (void)remove("test.db");

    printf(GREEN "test_block_manager_cursor passed\n" RESET);
}

void test_block_manager_count_blocks()
{
    block_manager_t *bm;
    if (block_manager_open(&bm, "test.db", 10000) != 0) return;

    for (int i = 0; i < 3; i++)
    {
        uint64_t size = 10;
        char data[10];
        snprintf(data, 10, "testdata%d", i);
        printf("data: %s\n", data);

        block_manager_block_t *block = block_manager_block_create(size, data);
        assert(block != NULL);

        assert(block_manager_block_write(bm, block, 1) != -1);
        (void)block_manager_block_free(block);
    }

    assert(block_manager_count_blocks(bm) == 3);

    assert(block_manager_close(bm) == 0);
    (void)remove("test.db");

    printf(GREEN "test_block_manager_count_blocks passed\n" RESET);
}

void test_block_manager_cursor_goto_first()
{
    block_manager_t *bm;
    if (block_manager_open(&bm, "test.db", 10000) != 0) return;

    for (int i = 0; i < 3; i++)
    {
        uint64_t size = 10;
        char data[10];
        snprintf(data, 10, "testdata%d", i);

        block_manager_block_t *block = block_manager_block_create(size, data);
        assert(block != NULL);

        assert(block_manager_block_write(bm, block, 1) != -1);
        (void)block_manager_block_free(block);
    }

    block_manager_cursor_t *cursor;
    if (block_manager_cursor_init(&cursor, bm) != 0)
    {
        block_manager_close(bm);
        return;
    }

    assert(block_manager_cursor_goto_first(cursor) == 0);

    block_manager_block_t *read_block = block_manager_cursor_read(cursor);
    assert(read_block != NULL);
    assert(memcmp(read_block->data, "testdata0", 10) == 0);
    (void)block_manager_block_free(read_block);

    (void)block_manager_cursor_free(cursor);
    assert(block_manager_close(bm) == 0);
    (void)remove("test.db");

    printf(GREEN "test_block_manager_cursor_goto_first passed\n" RESET);
}

void test_block_manager_cursor_goto_last()
{
    block_manager_t *bm;
    if (block_manager_open(&bm, "test.db", 10000) != 0) return;

    for (int i = 0; i < 3; i++)
    {
        uint64_t size = 10;
        char data[10];
        snprintf(data, 10, "testdata%d", i);

        block_manager_block_t *block = block_manager_block_create(size, data);
        assert(block != NULL);

        assert(block_manager_block_write(bm, block, 1) != -1);
        (void)block_manager_block_free(block);
    }

    block_manager_cursor_t *cursor;
    if (block_manager_cursor_init(&cursor, bm) != 0)
    {
        block_manager_close(bm);
        return;
    }

    assert(block_manager_cursor_goto_last(cursor) == 0);

    block_manager_block_t *read_block = block_manager_cursor_read(cursor);
    assert(read_block != NULL);

    assert(memcmp(read_block->data, "testdata2", 10) == 0);
    (void)block_manager_block_free(read_block);

    (void)block_manager_cursor_free(cursor);
    assert(block_manager_close(bm) == 0);
    (void)remove("test.db");

    printf(GREEN "test_block_manager_cursor_goto_last passed\n" RESET);
}

void test_block_manager_cursor_has_next()
{
    block_manager_t *bm;
    if (block_manager_open(&bm, "test.db", 10000) != 0) return;

    for (int i = 0; i < 3; i++)
    {
        uint64_t size = 10;
        char data[10];
        snprintf(data, 10, "testdata%d", i);

        block_manager_block_t *block = block_manager_block_create(size, data);
        assert(block != NULL);

        assert(block_manager_block_write(bm, block, 1) != -1);
        (void)block_manager_block_free(block);
    }

    block_manager_cursor_t *cursor;
    if (block_manager_cursor_init(&cursor, bm) != 0)
    {
        (void)block_manager_close(bm);
        return;
    }

    assert(block_manager_cursor_goto_first(cursor) == 0);
    assert(block_manager_cursor_has_next(cursor) == 1);

    assert(block_manager_cursor_next(cursor) == 0);
    assert(block_manager_cursor_has_next(cursor) == 1);

    assert(block_manager_cursor_next(cursor) == 0);
    assert(block_manager_cursor_has_next(cursor) == 1);

    (void)block_manager_cursor_free(cursor);
    assert(block_manager_close(bm) == 0);
    (void)remove("test.db");

    printf(GREEN "test_block_manager_cursor_has_next passed\n" RESET);
}

void test_block_manager_cursor_has_prev()
{
    block_manager_t *bm;
    if (block_manager_open(&bm, "test.db", 10000) != 0) return;

    for (int i = 0; i < 3; i++)
    {
        uint64_t size = 10;
        char data[10];
        snprintf(data, 10, "testdata%d", i);

        block_manager_block_t *block = block_manager_block_create(size, data);
        assert(block != NULL);

        assert(block_manager_block_write(bm, block, 1) != -1);
        (void)block_manager_block_free(block);
    }

    block_manager_cursor_t *cursor;
    if (block_manager_cursor_init(&cursor, bm) != 0)
    {
        (void)block_manager_close(bm);
        return;
    }

    assert(block_manager_cursor_goto_last(cursor) == 0);
    assert(block_manager_cursor_has_prev(cursor) == 1);

    assert(block_manager_cursor_prev(cursor) == 0);
    assert(block_manager_cursor_has_prev(cursor) == 1);

    assert(block_manager_cursor_prev(cursor) == 0);
    assert(block_manager_cursor_has_prev(cursor) == 0);

    (void)block_manager_cursor_free(cursor);
    assert(block_manager_close(bm) == 0);
    (void)remove("test.db");

    printf(GREEN "test_block_manager_cursor_has_prev passed\n" RESET);
}

void test_block_manager_cursor_position_checks()
{
    block_manager_t *bm;
    if (block_manager_open(&bm, "test.db", 10000) != 0) return;

    /* we write 3 blocks */
    for (int i = 0; i < 3; i++)
    {
        uint64_t size = 10;
        char data[10];
        snprintf(data, 10, "testdata%d", i);

        block_manager_block_t *block = block_manager_block_create(size, data);
        assert(block != NULL);

        assert(block_manager_block_write(bm, block, 1) != -1);
        (void)block_manager_block_free(block);
    }

    block_manager_cursor_t *cursor;
    if (block_manager_cursor_init(&cursor, bm) != 0)
    {
        (void)block_manager_close(bm);
        return;
    }

    /* test at_first */
    assert(block_manager_cursor_goto_first(cursor) == 0);
    assert(block_manager_cursor_at_first(cursor) == 1);
    assert(block_manager_cursor_at_second(cursor) == 0);
    assert(block_manager_cursor_at_last(cursor) == 0);

    /* test at_second */
    assert(block_manager_cursor_next(cursor) == 0);
    assert(block_manager_cursor_at_first(cursor) == 0);
    assert(block_manager_cursor_at_second(cursor) == 1);
    assert(block_manager_cursor_at_last(cursor) == 0);

    /* test at_last */
    assert(block_manager_cursor_next(cursor) == 0);
    assert(block_manager_cursor_at_first(cursor) == 0);
    assert(block_manager_cursor_at_second(cursor) == 0);
    assert(block_manager_cursor_at_last(cursor) == 1);

    (void)block_manager_cursor_free(cursor);
    assert(block_manager_close(bm) == 0);
    (void)remove("test.db");

    printf(GREEN "test_block_manager_cursor_position_checks passed\n" RESET);
}

void test_block_manager_get_size()
{
    block_manager_t *bm;
    if (block_manager_open(&bm, "test.db", 10000) != 0) return;

    uint64_t initial_size;
    assert(block_manager_get_size(bm, &initial_size) == 0);
    assert(initial_size == 0); /* file should be empty initially */

    /* we write some data and check size increases */
    for (int i = 0; i < 3; i++)
    {
        uint64_t size = 10;
        char data[10];
        snprintf(data, 10, "testdata%d", i);

        block_manager_block_t *block = block_manager_block_create(size, data);
        assert(block != NULL);

        assert(block_manager_block_write(bm, block, 1) != -1);
        (void)block_manager_block_free(block);
    }

    uint64_t after_write_size;
    assert(block_manager_get_size(bm, &after_write_size) == 0);
    assert(after_write_size > 0);

    assert(after_write_size == 54);

    /* we trunc and verify size is 0 again */
    assert(block_manager_truncate(bm) == 0);

    uint64_t after_truncate_size;
    assert(block_manager_get_size(bm, &after_truncate_size) == 0);
    assert(after_truncate_size == 0);

    assert(block_manager_close(bm) == 0);
    (void)remove("test.db");

    printf(GREEN "test_block_manager_get_size passed\n" RESET);
}

void test_block_manager_seek_and_goto()
{
    block_manager_t *bm;
    if (block_manager_open(&bm, "test.db", 10000) != 0) return;

    /* we write 3 blocks */
    long block_offsets[3];
    for (int i = 0; i < 3; i++)
    {
        uint64_t size = 10;
        char data[10];
        snprintf(data, 10, "testdata%d", i);

        block_manager_block_t *block = block_manager_block_create(size, data);
        assert(block != NULL);

        /* we save the offset for each block */
        block_offsets[i] = block_manager_block_write(bm, block, 1);
        assert(block_offsets[i] >= 0);
        (void)block_manager_block_free(block);
    }

    /* we test block_manager_seek **/
    assert(block_manager_seek(bm, block_offsets[1]) == 0);

    /* we read the block and verify */
    block_manager_block_t *read_block = block_manager_block_read(bm);
    assert(read_block != NULL);
    assert(memcmp(read_block->data, "testdata1", 10) == 0);
    (void)block_manager_block_free(read_block);

    /* we test block_manager_cursor_goto */
    block_manager_cursor_t *cursor;
    if (block_manager_cursor_init(&cursor, bm) != 0)
    {
        (void)block_manager_close(bm);
        return;
    }

    /* go to third block using its offset */
    assert(block_manager_cursor_goto(cursor, block_offsets[2]) == 0);

    /* we read the block and verify */
    read_block = block_manager_cursor_read(cursor);
    assert(read_block != NULL);
    assert(memcmp(read_block->data, "testdata2", 10) == 0);
    (void)block_manager_block_free(read_block);

    /* now go to first block */
    assert(block_manager_cursor_goto(cursor, block_offsets[0]) == 0);

    /* we read the block and verify */
    read_block = block_manager_cursor_read(cursor);
    assert(read_block != NULL);
    assert(memcmp(read_block->data, "testdata0", 10) == 0);
    (void)block_manager_block_free(read_block);

    (void)block_manager_cursor_free(cursor);
    assert(block_manager_close(bm) == 0);
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
        assert(block != NULL);

        (void)pthread_mutex_lock(&bm_mutex);

        long offset = block_manager_block_write(bm, block, 1);
        assert(offset != -1);

        (void)pthread_mutex_unlock(&bm_mutex);

        printf("Writer %d wrote block %d: %s\n", thread_id, i, data);

        (void)block_manager_block_free(block);

        usleep(rand() % 10000);
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
        usleep(rand() % 20000);
    }

    return NULL;
}

void test_block_manager_concurrent_rw()
{
    srand(time(NULL));

    /* we initialize the block manager */
    assert(block_manager_open(&bm, "concurrent_test.db", 10000) == 0);

    /* we create thread IDs */
    pthread_t writer_threads[NUM_WRITERS];
    pthread_t reader_threads[NUM_READERS];

    int writer_ids[NUM_WRITERS];
    int reader_ids[NUM_READERS];

    /* we start writer threads */
    for (int i = 0; i < NUM_WRITERS; i++)
    {
        writer_ids[i] = i;
        assert(pthread_create(&writer_threads[i], NULL, writer_thread, &writer_ids[i]) == 0);
    }

    /*we start reader threads */
    for (int i = 0; i < NUM_READERS; i++)
    {
        reader_ids[i] = i;
        assert(pthread_create(&reader_threads[i], NULL, reader_thread, &reader_ids[i]) == 0);
    }

    /* we wait for all threads to complete */
    for (int i = 0; i < NUM_WRITERS; i++)
    {
        assert(pthread_join(writer_threads[i], NULL) == 0);
    }

    for (int i = 0; i < NUM_READERS; i++)
    {
        assert(pthread_join(reader_threads[i], NULL) == 0);
    }

    /* we verify final state */
    int final_block_count = block_manager_count_blocks(bm);
    printf("Final block count: %d (expected: %d)\n", final_block_count,
           NUM_WRITERS * BLOCKS_PER_WRITER);
    assert(final_block_count == NUM_WRITERS * BLOCKS_PER_WRITER);

    printf("\nAll blocks in order:\n");
    block_manager_cursor_t *cursor;
    assert(block_manager_cursor_init(&cursor, bm) == 0);
    assert(block_manager_cursor_goto_first(cursor) == 0);

    block_manager_block_t *block;
    int block_index = 0;
    while ((block = block_manager_cursor_read(cursor)) != NULL)
    {
        printf("Block %d: %.*s\n", block_index++, (int)block->size, (char *)block->data);
        (void)block_manager_block_free(block);
        if (block_manager_cursor_next(cursor) != 0) break;
    }

    (void)block_manager_cursor_free(cursor);

    assert(block_manager_close(bm) == 0);
    (void)remove("concurrent_test.db");

    printf(GREEN "test_block_manager_concurrent_rw passed\n" RESET);
}

void test_block_manager_validate_last_block()
{
    printf("Testing block manager validation of last block...\n");

    /* first, create a block manager and write some valid blocks */
    block_manager_t *bm;
    assert(block_manager_open(&bm, "validate_test.db", 10000) == 0);

    /* we write 3 valid blocks */
    for (int i = 0; i < 3; i++)
    {
        uint64_t size = 10;
        char data[10];
        snprintf(data, 10, "testdata%d", i);

        block_manager_block_t *block = block_manager_block_create(size, data);
        assert(block != NULL);

        assert(block_manager_block_write(bm, block, 1) != -1);
        (void)block_manager_block_free(block);
    }

    assert(block_manager_close(bm) == 0);

    /* we now manually corrupt the file by appending just a size prefix without data */
    FILE *file = fopen("validate_test.db", "a+b");
    assert(file != NULL);

    /* we append just a size prefix (8 bytes) without the actual data */
    uint64_t corrupt_size = 100; /* size that's larger than what we'll actually write */
    assert(fwrite(&corrupt_size, sizeof(uint64_t), 1, file) == 1);

    /* we close the file */
    fclose(file);

    /* we get the file size after corruption */
    struct stat st;
    assert(stat("validate_test.db", &st) == 0);
    uint64_t corrupted_size = st.st_size;
    printf("File size after corruption: %lu bytes\n", corrupted_size);

    /* now reopen the block manager, which should validate and fix the last block */
    assert(block_manager_open(&bm, "validate_test.db", 10000) == 0);

    /* we get the file size after validation/repair */
    assert(stat("validate_test.db", &st) == 0);
    uint64_t repaired_size = st.st_size;
    printf("File size after repair: %lu bytes\n", repaired_size);

    /* the repaired size should be less than the corrupted size */
    assert(repaired_size < corrupted_size);

    /* we verify that exactly 3 blocks can be read */
    block_manager_cursor_t *cursor;
    assert(block_manager_cursor_init(&cursor, bm) == 0);

    /* we go to the first block */
    assert(block_manager_cursor_goto_first(cursor) == 0);

    /* we read and verify all blocks */
    int block_count = 0;
    for (int i = 0; i < 3; i++)
    {
        /* read the current block */
        block_manager_block_t *block = block_manager_cursor_read(cursor);
        assert(block != NULL);

        /* verify the block data */
        char expected[10];
        snprintf(expected, 10, "testdata%d", i);
        assert(block->size == 10);
        assert(memcmp(block->data, expected, 10) == 0);

        (void)block_manager_block_free(block);
        block_count++;

        /* we move to the next block if not the last one */
        if (i < 2)
        {
            assert(block_manager_cursor_next(cursor) == 0);
        }
    }

    assert(block_count == 3);

    /* we verify there are no more blocks (the corrupted one was removed) */
    int at_last = block_manager_cursor_at_last(cursor);
    printf("Cursor at last block: %d\n", at_last);
    assert(at_last == 1); /* should be at the last block */

    (void)block_manager_cursor_free(cursor);
    assert(block_manager_close(bm) == 0);
    remove("validate_test.db");

    printf(GREEN "test_block_manager_validate_last_block passed\n" RESET);
}

void test_block_manager_validation_edge_cases()
{
    printf("Testing block manager validation edge cases...\n");

    /** case 1
     * empty file */
    {
        /* create an empty file */
        FILE *file = fopen("empty_test.db", "wb");
        fclose(file);

        /* we open block manager on empty file (should pass validation) */
        block_manager_t *bm;
        assert(block_manager_open(&bm, "empty_test.db", 10000) == 0);

        /* we verify size is still 0 */
        uint64_t size;
        assert(block_manager_get_size(bm, &size) == 0);
        assert(size == 0);

        /* we close and clean up */
        assert(block_manager_close(bm) == 0);
        (void)remove("empty_test.db");
    }

    /** case 2
     * file with first block corrupted */
    {
        /* create a file with just a corrupted size header */
        FILE *file = fopen("corrupt_first.db", "wb");
        uint64_t corrupt_size = 1000;
        (void)fwrite(&corrupt_size, sizeof(uint64_t), 1, file);
        (void)fwrite("partial", 7, 1, file); /* write partial data, less than size */
        (void)fclose(file);

        /* we open block manager (should truncate to empty) */
        block_manager_t *bm;
        assert(block_manager_open(&bm, "corrupt_first.db", 10000) == 0);

        /* we verify size was truncated to 0 */
        uint64_t size;
        assert(block_manager_get_size(bm, &size) == 0);
        assert(size == 0);

        /* we close and clean up */
        assert(block_manager_close(bm) == 0);
        (void)remove("corrupt_first.db");
    }

    /** case 3
     * file with one good block and one corrupted block */
    {
        /* we create a block manager and write one valid block */
        block_manager_t *bm;
        assert(block_manager_open(&bm, "one_good_one_bad.db", 10000) == 0);

        /* we rrite a valid block */
        char data[10] = "goodblock";
        block_manager_block_t *block = block_manager_block_create(10, data);
        assert(block_manager_block_write(bm, block, 1) != -1);
        (void)block_manager_block_free(block);

        /* we close the block manager */
        assert(block_manager_close(bm) == 0);

        /* we manually append a corrupted block */
        FILE *file = fopen("one_good_one_bad.db", "a+b");
        uint64_t corrupt_size = 200;
        (void)fwrite(&corrupt_size, sizeof(uint64_t), 1, file);
        (void)fwrite("partial", 7, 1, file); /* we write partial data */
        (void)fclose(file);

        /* we get size before reopening */
        struct stat st;
        stat("one_good_one_bad.db", &st);
        uint64_t corrupted_size = st.st_size;

        /* we reopen with validation */
        assert(block_manager_open(&bm, "one_good_one_bad.db", 10000) == 0);

        /* we get size after reopening */
        stat("one_good_one_bad.db", &st);
        uint64_t repaired_size = st.st_size;

        /* we verify truncation happened */
        assert(repaired_size < corrupted_size);

        /* we verify only one block is readable */
        assert(block_manager_count_blocks(bm) == 1);

        assert(block_manager_close(bm) == 0);
        remove("one_good_one_bad.db");
    }

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
    int result = block_manager_open(&bm, long_path, 10000);

    /* might fail due to path length limits, but shouldn't crash */
    if (result == 0)
    {
        assert(block_manager_close(bm) == 0);
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
    assert(block_manager_open(&bm, "benchmark.db", 10000) == 0);

    uint8_t **block_data = malloc(NUM_BLOCKS * sizeof(uint8_t *));
    assert(block_data != NULL);

    for (int i = 0; i < NUM_BLOCKS; i++)
    {
        block_data[i] = malloc(BLOCK_SIZE);
        assert(block_data[i] != NULL);

        /* we fill with random data + sequential identifier */
        for (int j = 0; j < BLOCK_SIZE - 20; j++)
        {
            block_data[i][j] = rand() % 256;
        }

        /* we add identifier at the end of each block for verification */
        sprintf((char *)(block_data[i] + BLOCK_SIZE - 20), "block_%d", i);
    }

    printf(BOLDWHITE "Benchmark 1: Sequential Write Performance\n" RESET);

    long *block_offsets = malloc(NUM_BLOCKS * sizeof(long));
    assert(block_offsets != NULL);

    clock_t start_write = clock();

    for (int i = 0; i < NUM_BLOCKS; i++)
    {
        block_manager_block_t *block = block_manager_block_create(BLOCK_SIZE, block_data[i]);
        assert(block != NULL);

        block_offsets[i] = block_manager_block_write(bm, block, 1);
        assert(block_offsets[i] != -1);

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
    assert(block_manager_get_size(bm, &file_size) == 0);
    printf(BOLDWHITE "Database file size: %.2f MB\n" RESET, (float)file_size / (1024 * 1024));

    printf(BOLDWHITE "Benchmark 2: Sequential Read Performance\n" RESET);

    /* we reopen the database to ensure data is read from disk */
    assert(block_manager_close(bm) == 0);
    assert(block_manager_open(&bm, "benchmark.db", 10000) == 0);

    clock_t start_read_seq = clock();

    block_manager_cursor_t *cursor;
    assert(block_manager_cursor_init(&cursor, bm) == 0);
    assert(block_manager_cursor_goto_first(cursor) == 0);

    int blocks_read = 0;
    block_manager_block_t *block;

    while ((block = block_manager_cursor_read(cursor)) != NULL)
    {
        /* we verify block identifier */
        char expected_id[20];
        sprintf(expected_id, "block_%d", blocks_read);

        assert(memcmp((char *)(block->data + BLOCK_SIZE - 20), expected_id, strlen(expected_id)) ==
               0);

        (void)block_manager_block_free(block);
        blocks_read++;

        if (block_manager_cursor_next(cursor) != 0 || blocks_read >= NUM_BLOCKS)
        {
            break;
        }
    }

    assert(blocks_read == NUM_BLOCKS);
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
        int j = rand() % NUM_BLOCKS;
        long temp = block_offsets[i];
        block_offsets[i] = block_offsets[j];
        block_offsets[j] = temp;
    }

    /* init a cursor for random access */
    assert(block_manager_cursor_init(&cursor, bm) == 0);

    for (int i = 0; i < NUM_BLOCKS; i++)
    {
        /* we seek to the random offset */
        assert(block_manager_cursor_goto(cursor, block_offsets[i]) == 0);

        block = block_manager_cursor_read(cursor);
        assert(block != NULL);

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
    assert(count == NUM_BLOCKS);

    for (int i = 0; i < NUM_BLOCKS; i++)
    {
        free(block_data[i]);
    }
    free(block_data);
    free(block_offsets);

    assert(block_manager_close(bm) == 0);
    (void)remove("benchmark.db");

    printf(GREEN "benchmark_block_manager completed successfully\n" RESET);
}

int main(void)
{
    test_block_manager_open();
    test_block_manager_block_create();
    test_block_manager_block_write();
    test_block_manager_block_write_close_reopen_read();
    test_block_manager_truncate();
    test_block_manager_cursor();
    test_block_manager_count_blocks();
    test_block_manager_cursor_goto_first();
    test_block_manager_cursor_goto_last();
    test_block_manager_cursor_has_next();
    test_block_manager_cursor_has_prev();
    test_block_manager_cursor_position_checks();
    test_block_manager_get_size();
    test_block_manager_seek_and_goto();
    test_block_manager_open_safety();
    test_block_manager_validate_last_block();
    test_block_manager_validation_edge_cases();
    test_block_manager_concurrent_rw();

    srand(time(NULL));

    benchmark_block_manager();
    return 0;
}