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

/* context for cache eviction race test */
typedef struct
{
    block_manager_t *bm;
    int num_blocks;
    _Atomic(int) *errors;
    int thread_id;
} race_test_ctx_t;

/* thread function for cache eviction race test */
static void *race_reader_thread(void *arg)
{
    race_test_ctx_t *ctx = (race_test_ctx_t *)arg;

    /* each thread creates its own cursor - this matches the benchmark scenario */
    block_manager_cursor_t *cursor = NULL;
    if (block_manager_cursor_init(&cursor, ctx->bm) != 0)
    {
        atomic_fetch_add(ctx->errors, 1);
        return NULL;
    }

    /* each thread reads blocks sequentially, causing cache thrashing */
    for (int iteration = 0; iteration < 1000; iteration++)
    {
        /* reset cursor to beginning */
        if (block_manager_cursor_goto_first(cursor) != 0)
        {
            atomic_fetch_add(ctx->errors, 1);
            continue;
        }

        /* read through ALL blocks to maximize cache pressure */
        for (int b = 0; b < ctx->num_blocks; b++)
        {
            block_manager_block_t *block = block_manager_cursor_read(cursor);

            if (!block)
            {
                break; /* end of blocks */
            }

            /* simulate some work with the block */
            volatile int sum = 0;
            uint8_t *data = (uint8_t *)block->data;
            for (size_t i = 0; i < block->size && i < 100; i++)
            {
                sum += data[i];
            }

            /* release the block */
            block_manager_block_release(block);

            /* move to next block */
            if (block_manager_cursor_next(cursor) != 0)
            {
                break; /* no more blocks */
            }
        }

        /* NO delay - maximize race window */
    }

    block_manager_cursor_free(cursor);
    return NULL;
}

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
    (void)block_manager_block_release(block);
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

    (void)block_manager_block_release(block);

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

    (void)block_manager_block_release(block);

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

    (void)block_manager_block_release(block);
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

    (void)block_manager_block_release(block);

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

        (void)block_manager_block_release(block);
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

    (void)block_manager_block_release(read_block);

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

    (void)block_manager_block_release(read_block);

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

    (void)block_manager_block_release(read_block);

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

    (void)block_manager_block_release(read_block);

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

    (void)block_manager_block_release(read_block);

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
        (void)block_manager_block_release(block);
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
        (void)block_manager_block_release(block);
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
    (void)block_manager_block_release(read_block);

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
        (void)block_manager_block_release(block);
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
    (void)block_manager_block_release(read_block);

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
        (void)block_manager_block_release(block);
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
        (void)block_manager_block_release(block);
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
        (void)block_manager_block_release(block);
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
        (void)block_manager_block_release(block);
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
        (void)block_manager_block_release(block);
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
    (void)block_manager_block_release(read_block);

    /* go to third block using its offset */
    ASSERT_TRUE(block_manager_cursor_goto(cursor, (uint64_t)block_offsets[2]) == 0);

    /* we read the block and verify */
    read_block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(read_block != NULL);
    ASSERT_EQ(memcmp(read_block->data, "testdata2", 10), 0);
    (void)block_manager_block_release(read_block);

    /* now go to first block */
    ASSERT_TRUE(block_manager_cursor_goto(cursor, (uint64_t)block_offsets[0]) == 0);

    /* we read the block and verify */
    read_block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(read_block != NULL);
    ASSERT_EQ(memcmp(read_block->data, "testdata0", 10), 0);
    (void)block_manager_block_release(read_block);

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

        printf("Writer %d wrote block %d: %s\n", thread_id, i, data);

        (void)block_manager_block_release(block);

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
            printf("Reader %d read: %.*s\n", thread_id, (int)read_block->size,
                   (char *)read_block->data);
            (void)block_manager_block_release(read_block);
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
    int block_index = 0;
    while ((block = block_manager_cursor_read(cursor)) != NULL)
    {
        printf("Block %d: %.*s\n", block_index++, (int)block->size, (char *)block->data);
        (void)block_manager_block_release(block);
        if (block_manager_cursor_next(cursor) != 0) break;
    }

    (void)block_manager_cursor_free(cursor);

    ASSERT_TRUE(block_manager_close(bm) == 0);
    (void)remove("concurrent_test.db");
}

void test_block_manager_validate_last_block()
{
    block_manager_t *bm = NULL;
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
        (void)block_manager_block_release(block);
    }

    ASSERT_TRUE(block_manager_close(bm) == 0);

    /* we now manually corrupt the file by appending just a size prefix without data */
    FILE *file = fopen("validate_test.db", "a+b");
    ASSERT_TRUE(file != NULL);

    /* we append just a size prefix (8 bytes) without the actual data */
    uint64_t corrupt_size = 100; /* size that's larger than what we'll actually write */
    ASSERT_TRUE(fwrite(&corrupt_size, sizeof(uint64_t), 1, file) == 1);

    fclose(file);

    /* we get the file size after corruption */
    struct stat st;
    ASSERT_TRUE(stat("validate_test.db", &st) == 0);
    uint64_t corrupted_size = (uint64_t)st.st_size;
    printf("File size after corruption: %" PRIu64 " bytes\n", corrupted_size);

    /* now reopen the block manager, which should validate and fix the last block */
    ASSERT_TRUE(block_manager_open(&bm, "validate_test.db", BLOCK_MANAGER_SYNC_NONE) == 0);

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

        (void)block_manager_block_release(block);
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
            (void)block_manager_block_release(block);
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

        (void)block_manager_block_release(block);
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

        (void)block_manager_block_release(block);
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
        (void)block_manager_block_release(block);
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

void test_block_manager_lru_cache()
{
    block_manager_t *bm = NULL;

    ASSERT_TRUE(
        block_manager_open_with_cache(&bm, "cache_test.db", BLOCK_MANAGER_SYNC_NONE, 1024) == 0);
    ASSERT_TRUE(bm != NULL);
    ASSERT_TRUE(bm->block_manager_cache != NULL);
    ASSERT_TRUE(bm->block_manager_cache->lru_cache != NULL);
    ASSERT_EQ(bm->block_manager_cache->max_size, 1024);
    ASSERT_EQ(bm->block_manager_cache->current_size, 0);

    /* write several blocks that will exceed cache size */
    long block_offsets[5];
    for (int i = 0; i < 5; i++)
    {
        uint64_t size = 300; /* each block is 300 bytes */
        char data[300];
        snprintf(data, sizeof(data), "cached_block_%d_", i);

        for (int j = (int)strlen(data); j < 299; j++)
        {
            data[j] = 'A' + (i % 26);
        }
        data[299] = '\0';

        block_manager_block_t *block = block_manager_block_create(size, data);
        ASSERT_TRUE(block != NULL);

        block_offsets[i] = block_manager_block_write(bm, block);
        ASSERT_NE(block_offsets[i], -1);

        printf("Wrote block %d at offset %ld, cache size: %u\n", i, block_offsets[i],
               bm->block_manager_cache->current_size);

        (void)block_manager_block_release(block);
    }

    /* cache should have some blocks but not all (due to size limit) */
    printf("Final cache size: %u / %u bytes\n", bm->block_manager_cache->current_size,
           bm->block_manager_cache->max_size);
    ASSERT_TRUE(bm->block_manager_cache->current_size <= bm->block_manager_cache->max_size);

    /* test cache hit by reading recently written blocks */
    block_manager_cursor_t *cursor;
    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);

    /* read the last block (should be in cache) */
    ASSERT_TRUE(block_manager_cursor_goto(cursor, (uint64_t)block_offsets[4]) == 0);
    block_manager_block_t *read_block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(read_block != NULL);
    ASSERT_EQ(read_block->size, 300);

    /* verify content */
    char expected[300];
    snprintf(expected, sizeof(expected), "cached_block_4_");
    for (int j = (int)strlen(expected); j < 299; j++)
    {
        expected[j] = 'A' + (4 % 26);
    }
    expected[299] = '\0';

    ASSERT_EQ(memcmp(read_block->data, expected, 300), 0);
    (void)block_manager_block_release(read_block);

    /* read all blocks to test cache behavior */
    for (int i = 0; i < 5; i++)
    {
        ASSERT_TRUE(block_manager_cursor_goto(cursor, (uint64_t)block_offsets[i]) == 0);
        read_block = block_manager_cursor_read(cursor);
        ASSERT_TRUE(read_block != NULL);
        ASSERT_EQ(read_block->size, 300);

        /* verify content matches what we wrote */
        snprintf(expected, sizeof(expected), "cached_block_%d_", i);
        for (int j = (int)strlen(expected); j < 299; j++)
        {
            expected[j] = 'A' + (i % 26);
        }
        expected[299] = '\0';

        ASSERT_EQ(memcmp(read_block->data, expected, 300), 0);
        (void)block_manager_block_release(read_block);

        printf("Successfully read block %d from offset %ld\n", i, block_offsets[i]);
    }

    (void)block_manager_cursor_free(cursor);

    /* test cache behavior with truncate */
    uint32_t cache_size_before_truncate = bm->block_manager_cache->current_size;
    printf("Cache size before truncate: %u\n", cache_size_before_truncate);

    ASSERT_TRUE(block_manager_truncate(bm) == 0);

    /* cache should be cleared after truncate */
    ASSERT_EQ(bm->block_manager_cache->current_size, 0);
    printf("Cache size after truncate: %u\n", bm->block_manager_cache->current_size);

    ASSERT_TRUE(block_manager_close(bm) == 0);

    ASSERT_TRUE(block_manager_open(&bm, "cache_test.db", BLOCK_MANAGER_SYNC_NONE) == 0);
    ASSERT_TRUE(bm != NULL);
    ASSERT_TRUE(bm->block_manager_cache == NULL); /* no cache should be allocated */

    uint64_t size = 100;
    char data[100] = "no_cache_block";
    block_manager_block_t *block = block_manager_block_create(size, data);
    ASSERT_TRUE(block != NULL);

    long offset = block_manager_block_write(bm, block);
    ASSERT_NE(offset, -1);
    (void)block_manager_block_release(block);

    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);
    ASSERT_TRUE(block_manager_cursor_goto(cursor, (uint64_t)offset) == 0);
    read_block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(read_block != NULL);
    ASSERT_EQ(read_block->size, 100);
    ASSERT_EQ(memcmp(read_block->data, "no_cache_block", 14), 0);

    (void)block_manager_block_release(read_block);
    (void)block_manager_cursor_free(cursor);
    ASSERT_TRUE(block_manager_close(bm) == 0);

    (void)remove("cache_test.db");
}

void test_block_manager_lru_cache_edge_cases()
{
    block_manager_t *bm = NULL;

    /* zero  cache size (should work without caching) */
    printf("Test 1: Zero cache size\n");
    ASSERT_TRUE(block_manager_open_with_cache(&bm, "edge_test.db", BLOCK_MANAGER_SYNC_NONE, 0) ==
                0);
    ASSERT_TRUE(bm != NULL);
    ASSERT_TRUE(bm->block_manager_cache == NULL); /* cache should not be allocated */

    /* write and read should work normally */
    uint64_t size = 100;
    char data[100] = "zero_cache_test";
    block_manager_block_t *block = block_manager_block_create(size, data);
    ASSERT_TRUE(block != NULL);

    long offset = block_manager_block_write(bm, block);
    ASSERT_NE(offset, -1);
    (void)block_manager_block_release(block);

    block_manager_cursor_t *cursor;
    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);
    ASSERT_TRUE(block_manager_cursor_goto(cursor, (uint64_t)offset) == 0);
    block_manager_block_t *read_block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(read_block != NULL);
    ASSERT_EQ(memcmp(read_block->data, "zero_cache_test", 15), 0);

    (void)block_manager_block_release(read_block);
    (void)block_manager_cursor_free(cursor);
    ASSERT_TRUE(block_manager_close(bm) == 0);
    (void)remove("edge_test.db");

    /* test very small cache with large blocks (blocks larger than cache) */
    printf("Test 2: Large blocks with small cache\n");
    ASSERT_TRUE(block_manager_open_with_cache(&bm, "edge_test.db", BLOCK_MANAGER_SYNC_NONE, 50) ==
                0);
    ASSERT_TRUE(bm->block_manager_cache != NULL);
    ASSERT_EQ(bm->block_manager_cache->max_size, 50);

    /* write a block larger than cache size */
    size = 200;
    char large_data[200];
    memset(large_data, 'X', 199);
    large_data[199] = '\0';

    block = block_manager_block_create(size, large_data);
    ASSERT_TRUE(block != NULL);

    offset = block_manager_block_write(bm, block);
    ASSERT_NE(offset, -1);
    (void)block_manager_block_release(block);

    /* cache should remain empty since block is too large */
    ASSERT_EQ(bm->block_manager_cache->current_size, 0);
    printf("Cache size after writing large block: %u (expected: 0)\n",
           bm->block_manager_cache->current_size);

    /* reading should still work */
    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);
    ASSERT_TRUE(block_manager_cursor_goto(cursor, (uint64_t)offset) == 0);
    read_block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(read_block != NULL);
    ASSERT_EQ(read_block->size, 200);

    (void)block_manager_block_release(read_block);
    (void)block_manager_cursor_free(cursor);
    ASSERT_TRUE(block_manager_close(bm) == 0);
    (void)remove("edge_test.db");

    /*cache eviction behavior (lru) */
    printf("Test 3: Cache eviction behavior\n");
    ASSERT_TRUE(block_manager_open_with_cache(&bm, "edge_test.db", BLOCK_MANAGER_SYNC_NONE, 250) ==
                0);

    /* write 4 blocks of 100 bytes each -- only 2 should fit in cache */
    long block_offsets[4];
    for (int i = 0; i < 4; i++)
    {
        size = 100;
        char block_data[100];
        snprintf(block_data, sizeof(block_data), "eviction_test_block_%d", i);
        memset(block_data + strlen(block_data), 'A' + i, 99 - strlen(block_data));
        block_data[99] = '\0';

        block = block_manager_block_create(size, block_data);
        ASSERT_TRUE(block != NULL);

        block_offsets[i] = block_manager_block_write(bm, block);
        ASSERT_NE(block_offsets[i], -1);
        (void)block_manager_block_release(block);

        printf("Wrote eviction test block %d, cache size: %u\n", i,
               bm->block_manager_cache->current_size);
    }

    /* cache should be at or near capacity */
    ASSERT_TRUE(bm->block_manager_cache->current_size <= bm->block_manager_cache->max_size);
    printf("Final cache size: %u / %u\n", bm->block_manager_cache->current_size,
           bm->block_manager_cache->max_size);

    /* read all blocks -- this should trigger cache hits and misses */
    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);
    for (int i = 0; i < 4; i++)
    {
        ASSERT_TRUE(block_manager_cursor_goto(cursor, (uint64_t)block_offsets[i]) == 0);
        read_block = block_manager_cursor_read(cursor);
        ASSERT_TRUE(read_block != NULL);
        ASSERT_EQ(read_block->size, 100);

        char expected[100];
        snprintf(expected, sizeof(expected), "eviction_test_block_%d", i);
        ASSERT_EQ(memcmp(read_block->data, expected, strlen(expected)), 0);

        (void)block_manager_block_release(read_block);
        printf("Successfully read eviction test block %d\n", i);
    }

    (void)block_manager_cursor_free(cursor);

    /* multiple reads of same block (should hit cache) */
    printf("Test 4: Multiple reads of same block\n");
    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);

    /* read the same block multiple times */
    for (int i = 0; i < 3; i++)
    {
        ASSERT_TRUE(block_manager_cursor_goto(cursor, (uint64_t)block_offsets[3]) == 0);
        read_block = block_manager_cursor_read(cursor);
        ASSERT_TRUE(read_block != NULL);
        ASSERT_EQ(read_block->size, 100);
        (void)block_manager_block_release(read_block);
        printf("Read same block iteration %d\n", i + 1);
    }

    (void)block_manager_cursor_free(cursor);

    /* test lru behavior with sync modes */
    printf("Test 5: Cache with different sync modes\n");
    ASSERT_TRUE(block_manager_close(bm) == 0);
    (void)remove("edge_test.db");

    /* test with full sync mode */
    ASSERT_TRUE(block_manager_open_with_cache(&bm, "edge_test.db", BLOCK_MANAGER_SYNC_FULL, 500) ==
                0);
    ASSERT_TRUE(bm->block_manager_cache != NULL);

    size = 100;
    char sync_data[100] = "sync_mode_test";
    block = block_manager_block_create(size, sync_data);
    ASSERT_TRUE(block != NULL);

    offset = block_manager_block_write(bm, block);
    ASSERT_NE(offset, -1);
    (void)block_manager_block_release(block);

    /* cache should work with sync mode */
    ASSERT_TRUE(bm->block_manager_cache->current_size > 0);
    printf("Cache size with sync mode: %u\n", bm->block_manager_cache->current_size);

    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);
    ASSERT_TRUE(block_manager_cursor_goto(cursor, (uint64_t)offset) == 0);
    read_block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(read_block != NULL);
    ASSERT_EQ(memcmp(read_block->data, "sync_mode_test", 14), 0);

    (void)block_manager_block_release(read_block);
    (void)block_manager_cursor_free(cursor);
    ASSERT_TRUE(block_manager_close(bm) == 0);
    (void)remove("edge_test.db");
}

void test_block_manager_cache_concurrent()
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open_with_cache(&bm, "cache_concurrent_test.db",
                                              BLOCK_MANAGER_SYNC_NONE, 2048) == 0);
    ASSERT_TRUE(bm->block_manager_cache != NULL);

    long initial_offsets[5];
    for (int i = 0; i < 5; i++)
    {
        uint64_t size = 200;
        char data[200];
        snprintf(data, sizeof(data), "concurrent_cache_block_%d_", i);
        memset(data + strlen(data), 'A' + i, 199 - strlen(data));
        data[199] = '\0';

        block_manager_block_t *block = block_manager_block_create(size, data);
        ASSERT_TRUE(block != NULL);

        initial_offsets[i] = block_manager_block_write(bm, block);
        ASSERT_NE(initial_offsets[i], -1);
        (void)block_manager_block_release(block);
    }

    printf("Initial cache size: %u / %u\n", bm->block_manager_cache->current_size,
           bm->block_manager_cache->max_size);

    /* test concurrent reads -- simulate multiple threads reading cached blocks */
    block_manager_cursor_t *cursors[3];
    for (int i = 0; i < 3; i++)
    {
        ASSERT_TRUE(block_manager_cursor_init(&cursors[i], bm) == 0);
    }

    /* each cursor reads different blocks multiple times */
    for (int round = 0; round < 3; round++)
    {
        for (int cursor_id = 0; cursor_id < 3; cursor_id++)
        {
            int block_idx = (cursor_id + round) % 5;
            ASSERT_TRUE(block_manager_cursor_goto(cursors[cursor_id],
                                                  (uint64_t)initial_offsets[block_idx]) == 0);

            block_manager_block_t *read_block = block_manager_cursor_read(cursors[cursor_id]);
            ASSERT_TRUE(read_block != NULL);
            ASSERT_EQ(read_block->size, 200);

            char expected[200];
            snprintf(expected, sizeof(expected), "concurrent_cache_block_%d_", block_idx);
            ASSERT_EQ(memcmp(read_block->data, expected, strlen(expected)), 0);

            (void)block_manager_block_release(read_block);
            printf("Cursor %d read block %d in round %d\n", cursor_id, block_idx, round);
        }
    }

    for (int i = 0; i < 3; i++)
    {
        (void)block_manager_cursor_free(cursors[i]);
    }

    /* test cache behavior during writes while reading */
    block_manager_cursor_t *reader_cursor;
    ASSERT_TRUE(block_manager_cursor_init(&reader_cursor, bm) == 0);

    /* write new blocks while reading existing ones */
    for (int i = 0; i < 3; i++)
    {
        ASSERT_TRUE(block_manager_cursor_goto(reader_cursor, (uint64_t)initial_offsets[i % 5]) ==
                    0);
        block_manager_block_t *read_block = block_manager_cursor_read(reader_cursor);
        ASSERT_TRUE(read_block != NULL);
        (void)block_manager_block_release(read_block);

        uint64_t size = 150;
        char data[150];
        snprintf(data, sizeof(data), "new_concurrent_block_%d", i);
        memset(data + strlen(data), 'X', 149 - strlen(data));
        data[149] = '\0';

        block_manager_block_t *new_block = block_manager_block_create(size, data);
        ASSERT_TRUE(new_block != NULL);

        long new_offset = block_manager_block_write(bm, new_block);
        ASSERT_NE(new_offset, -1);
        (void)block_manager_block_release(new_block);

        printf("Wrote new block %d while reading, cache size: %u\n", i,
               bm->block_manager_cache->current_size);
    }

    (void)block_manager_cursor_free(reader_cursor);

    /* verify cache is still within limits */
    ASSERT_TRUE(bm->block_manager_cache->current_size <= bm->block_manager_cache->max_size);
    printf("Final cache size: %u / %u\n", bm->block_manager_cache->current_size,
           bm->block_manager_cache->max_size);

    ASSERT_TRUE(block_manager_close(bm) == 0);
    (void)remove("cache_concurrent_test.db");
}

/* stress test for cache eviction race conditions */
#define STRESS_NUM_THREADS 8
#define STRESS_ITERATIONS  1000
#define STRESS_CACHE_SIZE  512 /* small cache to force evictions */

typedef struct
{
    block_manager_t *bm;
    int thread_id;
    uint64_t *offsets;
    int num_blocks;
} stress_thread_args_t;

static void *cache_stress_thread(void *arg)
{
    stress_thread_args_t *args = (stress_thread_args_t *)arg;

    /* Each thread gets its own cursor */
    block_manager_cursor_t *cursor;
    if (block_manager_cursor_init(&cursor, args->bm) != 0)
    {
        return NULL;
    }

    for (int i = 0; i < STRESS_ITERATIONS; i++)
    {
        /* Read random blocks to cause cache hits and misses */
        int block_idx = rand() % args->num_blocks;

        if (block_manager_cursor_goto(cursor, args->offsets[block_idx]) == 0)
        {
            block_manager_block_t *block = block_manager_cursor_read(cursor);

            if (block != NULL)
            {
                /* Verify block content */
                char expected[64];
                snprintf(expected, sizeof(expected), "stress_block_%d", block_idx);

                if (memcmp(block->data, expected, strlen(expected)) != 0)
                {
                    printf("Thread %d: Block %d content mismatch!\n", args->thread_id, block_idx);
                }

                /* Small delay to increase chance of race */
                for (volatile int j = 0; j < 100; j++)
                    ;

                block_manager_block_release(block);
            }
        }
    }

    block_manager_cursor_free(cursor);
    return NULL;
}

void test_block_manager_cache_race_stress()
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open_with_cache(&bm, "cache_stress_test.db", BLOCK_MANAGER_SYNC_NONE,
                                              STRESS_CACHE_SIZE) == 0);

    /* write blocks that will fit in cache initially but cause evictions */
#define STRESS_NUM_BLOCKS 20 /* more blocks than cache can hold */
    uint64_t offsets[STRESS_NUM_BLOCKS];

    for (int i = 0; i < STRESS_NUM_BLOCKS; i++)
    {
        char data[64];
        snprintf(data, sizeof(data), "stress_block_%d", i);

        block_manager_block_t *block = block_manager_block_create(64, data);
        ASSERT_TRUE(block != NULL);

        offsets[i] = block_manager_block_write(bm, block);
        ASSERT_TRUE(offsets[i] != (uint64_t)-1);

        block_manager_block_release(block);
    }

    printf("Starting cache stress test with %d threads, %d iterations each...\n",
           STRESS_NUM_THREADS, STRESS_ITERATIONS);

    /* Create threads that will hammer the cache */
    pthread_t threads[STRESS_NUM_THREADS];
    stress_thread_args_t args[STRESS_NUM_THREADS];

    for (int i = 0; i < STRESS_NUM_THREADS; i++)
    {
        args[i].bm = bm;
        args[i].thread_id = i;
        args[i].offsets = offsets;
        args[i].num_blocks = STRESS_NUM_BLOCKS;

        ASSERT_TRUE(pthread_create(&threads[i], NULL, cache_stress_thread, &args[i]) == 0);
    }

    /* Wait for all threads */
    for (int i = 0; i < STRESS_NUM_THREADS; i++)
    {
        ASSERT_TRUE(pthread_join(threads[i], NULL) == 0);
    }

    printf("Cache stress test completed successfully\n");

    ASSERT_TRUE(block_manager_close(bm) == 0);
    (void)remove("cache_stress_test.db");
}

void benchmark_block_manager_with_cache()
{
    block_manager_t *bm = NULL;

    uint32_t cache_size = 10 * 1024 * 1024;
    ASSERT_TRUE(block_manager_open_with_cache(&bm, "benchmark_cache.db", BLOCK_MANAGER_SYNC_NONE,
                                              cache_size) == 0);

    uint8_t **block_data = malloc(NUM_BLOCKS * sizeof(uint8_t *));
    ASSERT_TRUE(block_data != NULL);

    for (int i = 0; i < NUM_BLOCKS; i++)
    {
        block_data[i] = malloc(BLOCK_SIZE);
        ASSERT_TRUE(block_data[i] != NULL);

        /* fill with random data + sequential identifier */
        for (int j = 0; j < BLOCK_SIZE - 20; j++)
        {
            block_data[i][j] = (uint8_t)(rand() % 256);
        }

        /* add identifier at the end of each block for verification */
        snprintf((char *)(block_data[i] + BLOCK_SIZE - 20), 20, "cached_%d", i);
    }

    printf(BOLDWHITE "Cached Benchmark 1: Sequential Write Performance (with caching)\n" RESET);
    printf("Cache size: %u bytes (%.2f MB)\n", cache_size, (float)cache_size / (1024 * 1024));

    long *block_offsets = malloc(NUM_BLOCKS * sizeof(long));
    ASSERT_TRUE(block_offsets != NULL);

    clock_t start_write = clock();

    for (int i = 0; i < NUM_BLOCKS; i++)
    {
        block_manager_block_t *block = block_manager_block_create(BLOCK_SIZE, block_data[i]);
        ASSERT_TRUE(block != NULL);

        block_offsets[i] = block_manager_block_write(bm, block);
        ASSERT_NE(block_offsets[i], -1);

        (void)block_manager_block_release(block);

        if (i % 10000 == 0 && i > 0)
        {
            printf("Wrote %d blocks, cache usage: %u / %u bytes (%.1f%%)\n", i,
                   bm->block_manager_cache->current_size, bm->block_manager_cache->max_size,
                   (float)bm->block_manager_cache->current_size /
                       bm->block_manager_cache->max_size * 100);
        }
    }

    clock_t end_write = clock();
    double time_spent_write = (double)(end_write - start_write) / CLOCKS_PER_SEC;

    printf(CYAN "Writing %d blocks (%d bytes each) with cache took %.3f seconds\n", NUM_BLOCKS,
           BLOCK_SIZE, time_spent_write);
    if (time_spent_write > 0.0)
    {
        printf("Cached write throughput: %.2f blocks/second\n", NUM_BLOCKS / time_spent_write);
        printf("Cached write throughput: %.2f MB/second\n" RESET,
               (NUM_BLOCKS * BLOCK_SIZE) / (time_spent_write * 1024 * 1024));
    }
    else
    {
        printf("Cached write throughput: N/A (completed too fast to measure)\n" RESET);
    }

    printf("Final cache usage: %u / %u bytes (%.1f%%)\n", bm->block_manager_cache->current_size,
           bm->block_manager_cache->max_size,
           (float)bm->block_manager_cache->current_size / bm->block_manager_cache->max_size * 100);

    printf(BOLDWHITE
           "Cached Benchmark 2: Sequential Read Performance (cache hits expected)\n" RESET);

    clock_t start_read_seq = clock();

    block_manager_cursor_t *cursor;
    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);
    ASSERT_TRUE(block_manager_cursor_goto_first(cursor) == 0);

    int blocks_read = 0;
    block_manager_block_t *block;

    while ((block = block_manager_cursor_read(cursor)) != NULL)
    {
        /* verify block identifier */
        char expected_id[20];
        snprintf(expected_id, sizeof(expected_id), "cached_%d", blocks_read);

        ASSERT_TRUE(
            memcmp((char *)block->data + BLOCK_SIZE - 20, expected_id, strlen(expected_id)) == 0);

        (void)block_manager_block_release(block);
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

    printf(CYAN "Sequentially reading %d blocks with cache took %.3f seconds\n", NUM_BLOCKS,
           time_spent_read_seq);
    if (time_spent_read_seq > 0.0)
    {
        printf("Cached sequential read throughput: %.2f blocks/second\n",
               NUM_BLOCKS / time_spent_read_seq);
        printf("Cached sequential read throughput: %.2f MB/second\n" RESET,
               (NUM_BLOCKS * BLOCK_SIZE) / (time_spent_read_seq * 1024 * 1024));
    }
    else
    {
        printf("Cached sequential read throughput: N/A (completed too fast to measure)\n" RESET);
    }

    printf(BOLDWHITE "Cached Benchmark 3: Random Read Performance (cache behavior test)\n" RESET);

    clock_t start_read_random = clock();

    /* shuffle the offsets array to randomize access */
    for (int i = 0; i < NUM_BLOCKS; i++)
    {
        int j = rand() % NUM_BLOCKS;
        long temp = block_offsets[i];
        block_offsets[i] = block_offsets[j];
        block_offsets[j] = temp;
    }

    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);

    int cache_hits_expected = 0;
    for (int i = 0; i < NUM_BLOCKS; i++)
    {
        /* seek to the random offset */
        ASSERT_TRUE(block_manager_cursor_goto(cursor, (uint64_t)block_offsets[i]) == 0);

        block = block_manager_cursor_read(cursor);
        ASSERT_TRUE(block != NULL);

        /* count potential cache hits (blocks that might still be in cache) */
        uint32_t blocks_in_cache = cache_size / bm->block_size;
        uint32_t cache_threshold =
            (blocks_in_cache >= NUM_BLOCKS) ? 0 : (NUM_BLOCKS - blocks_in_cache);
        if ((uint32_t)i >= cache_threshold)
        {
            cache_hits_expected++;
        }

        (void)block_manager_block_release(block);
    }

    (void)block_manager_cursor_free(cursor);

    clock_t end_read_random = clock();
    double time_spent_read_random = (double)(end_read_random - start_read_random) / CLOCKS_PER_SEC;

    printf(CYAN "Randomly reading %d blocks with cache took %.3f seconds\n", NUM_BLOCKS,
           time_spent_read_random);
    if (time_spent_read_random > 0.0)
    {
        printf("Cached random read throughput: %.2f blocks/second\n",
               NUM_BLOCKS / time_spent_read_random);
        printf("Cached random read throughput: %.2f MB/second\n",
               (NUM_BLOCKS * BLOCK_SIZE) / (time_spent_read_random * 1024 * 1024));
    }
    else
    {
        printf("Cached random read throughput: N/A (completed too fast to measure)\n");
    }
    printf("Estimated cache hits: %d/%d (%.1f%%)\n" RESET, cache_hits_expected, NUM_BLOCKS,
           (float)cache_hits_expected / NUM_BLOCKS * 100);

    printf(BOLDWHITE "Cached Benchmark 4: Repeated Access Pattern (cache hit test)\n" RESET);

    /* testt reading the same subset of blocks multiple times */
    uint32_t blocks_that_fit = cache_size / bm->block_size;
    int subset_size = (int)(blocks_that_fit / 2);
    if (subset_size > NUM_BLOCKS) subset_size = NUM_BLOCKS;
    if (subset_size <= 0) subset_size = 1;

    clock_t start_repeated = clock();

    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);

    /* read the same subset 3 times */
    for (int round = 0; round < 3; round++)
    {
        for (int i = 0; i < subset_size; i++)
        {
            ASSERT_TRUE(block_manager_cursor_goto(cursor, (uint64_t)block_offsets[i]) == 0);
            block = block_manager_cursor_read(cursor);
            ASSERT_TRUE(block != NULL);
            (void)block_manager_block_release(block);
        }
    }

    (void)block_manager_cursor_free(cursor);

    clock_t end_repeated = clock();
    double time_spent_repeated = (double)(end_repeated - start_repeated) / CLOCKS_PER_SEC;

    printf(CYAN "Reading %d blocks 3 times (cache hit test) took %.3f seconds\n", subset_size,
           time_spent_repeated);
    if (time_spent_repeated > 0.0)
    {
        printf("Repeated access throughput: %.2f blocks/second\n",
               (subset_size * 3) / time_spent_repeated);
        printf("Repeated access throughput: %.2f MB/second\n" RESET,
               (subset_size * 3 * BLOCK_SIZE) / (time_spent_repeated * 1024 * 1024));
    }
    else
    {
        printf(YELLOW "Repeated access throughput: N/A (completed too fast to measure)\n" RESET);
    }

    for (int i = 0; i < NUM_BLOCKS; i++)
    {
        free(block_data[i]);
    }
    free(block_data);
    free(block_offsets);

    ASSERT_TRUE(block_manager_close(bm) == 0);
    (void)remove("benchmark_cache.db");
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
            block_manager_block_release(block);
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

    block_manager_block_release(block);
    block_manager_close(bm_none);
    remove("test_sync_none.db");

    /* test SYNC_FULL */
    block_manager_t *bm_full = NULL;
    ASSERT_EQ(block_manager_open(&bm_full, "test_sync_full.db", BLOCK_MANAGER_SYNC_FULL), 0);

    block = block_manager_block_create(10, (uint8_t *)"test_data");
    ASSERT_TRUE(block != NULL);
    offset = block_manager_block_write(bm_full, block);
    ASSERT_TRUE(offset != -1);

    block_manager_block_release(block);
    block_manager_close(bm_full);
    remove("test_sync_full.db");
}

void test_block_manager_overflow_blocks()
{
    block_manager_t *bm = NULL;
    ASSERT_EQ(block_manager_open(&bm, "test_overflow.db", BLOCK_MANAGER_SYNC_NONE), 0);

    /* create block larger than MAX_INLINE_BLOCK_SIZE (32KB) */
    uint64_t large_size = 64 * 1024; /* 64KB */
    uint8_t *large_data = malloc(large_size);
    memset(large_data, 'X', large_size);

    block_manager_block_t *block = block_manager_block_create(large_size, large_data);
    ASSERT_TRUE(block != NULL);
    int64_t offset = block_manager_block_write(bm, block);
    ASSERT_TRUE(offset != -1);

    /* read it back using cursor */
    block_manager_cursor_t *cursor;
    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);
    ASSERT_TRUE(block_manager_cursor_goto(cursor, (uint64_t)offset) == 0);

    block_manager_block_t *read_block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(read_block != NULL);
    ASSERT_EQ(read_block->size, large_size);
    ASSERT_EQ(memcmp(read_block->data, large_data, large_size), 0);

    block_manager_block_release(read_block);
    block_manager_cursor_free(cursor);
    free(large_data);
    block_manager_block_release(block);
    block_manager_close(bm);
    remove("test_overflow.db");
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
                    block_manager_block_release(read_block);
                }
            }
            block_manager_cursor_free(cursor);
        }
    }

    block_manager_block_release(block);
    block_manager_close(bm);
    remove("test_empty.db");
}

void benchmark_block_manager_parallel_write(void)
{
    block_manager_t *bm = NULL;
    (void)remove("test_parallel.db");
    ASSERT_TRUE(block_manager_open_with_cache(&bm, "test_parallel.db", 0, 0) == 0);

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

/**
 * test_block_manager_cache_eviction_race
 * reproduces the race condition where a block is evicted from cache
 * while another thread is trying to acquire a reference to it
 */
void test_block_manager_cache_eviction_race()
{
    block_manager_t *bm = NULL;

    /* create block manager with small cache to force evictions */
    ASSERT_TRUE(block_manager_open(&bm, "test_eviction_race.db", BLOCK_MANAGER_SYNC_NONE) == 0);

    /* set up a VERY small cache to force constant evictions */
    block_manager_cache_t *cache = malloc(sizeof(block_manager_cache_t));
    cache->max_size = 2 * 1024; /* 2KB cache - very small! */
    cache->current_size = 0;
    cache->lru_cache = lru_cache_new(2); /* only 2 slots! */
    bm->block_manager_cache = cache;

    /* write several blocks (more than cache can hold) */
    const int num_blocks = 10;

    for (int i = 0; i < num_blocks; i++)
    {
        char data[1024];
        snprintf(data, sizeof(data), "Block %d data", i);

        block_manager_block_t *block = block_manager_block_create(1024, (uint8_t *)data);
        ASSERT_TRUE(block != NULL);

        int64_t offset = block_manager_block_write(bm, block);
        ASSERT_TRUE(offset >= 0);

        block_manager_block_release(block);
    }

    _Atomic(int) errors = 0;

    /* create multiple threads to trigger the race - each with its own cursor */
    const int num_threads = 8;
    pthread_t threads[8];
    race_test_ctx_t contexts[8];

    for (int i = 0; i < num_threads; i++)
    {
        contexts[i].bm = bm;
        contexts[i].num_blocks = num_blocks;
        contexts[i].errors = &errors;
        contexts[i].thread_id = i;

        pthread_create(&threads[i], NULL, race_reader_thread, &contexts[i]);
    }

    /* wait for all threads */
    for (int i = 0; i < num_threads; i++)
    {
        pthread_join(threads[i], NULL);
    }

    /* if we get here without ASAN errors, the race is fixed */
    printf("  Cache eviction race test completed with %d errors\n", atomic_load(&errors));
    ASSERT_EQ(atomic_load(&errors), 0);

    ASSERT_TRUE(block_manager_close(bm) == 0);
    (void)remove("test_eviction_race.db");
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
    RUN_TEST(test_block_manager_lru_cache, tests_passed);
    RUN_TEST(test_block_manager_lru_cache_edge_cases, tests_passed);
    RUN_TEST(test_block_manager_cache_concurrent, tests_passed);
    RUN_TEST(test_block_manager_cache_concurrent, tests_passed);
    RUN_TEST(test_block_manager_cache_race_stress, tests_passed);
    RUN_TEST(test_block_manager_concurrent_rw, tests_passed);
    RUN_TEST(test_block_manager_sync_modes, tests_passed);
    RUN_TEST(test_block_manager_overflow_blocks, tests_passed);
    RUN_TEST(test_block_manager_empty_block, tests_passed);
    RUN_TEST(test_block_manager_cache_eviction_race, tests_passed);

    srand((unsigned int)time(NULL)); /* NOLINT(cert-msc51-cpp) */
    RUN_TEST(benchmark_block_manager, tests_passed);
    RUN_TEST(benchmark_block_manager_with_cache, tests_passed);
    RUN_TEST(benchmark_block_manager_parallel_write, tests_passed);

    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}