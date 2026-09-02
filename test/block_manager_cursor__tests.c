/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include "../src/io/block_manager.h"
#include "test_utils.h"

/* the block manager's forward and backward cursor, split out from the block manager suite so each
 * file covers one part of the module the way src/io is itself split. these cases drive positioning,
 * traversal and the read at a position; the write, recovery and concurrency cases stay next to the
 * code they exercise. */

static int tests_passed = 0;
static int tests_failed = 0;

/* distinct from the fixture the block manager suite uses, so ctest can run the two in parallel
 * without them tearing down each other's file mid-test */
#define CURSOR_TEST_FILE "test_bm_cursor.db"

void test_block_manager_cursor()
{
    /* we create a block manager, write a few blocks and verify forward and backward iteration */

    block_manager_t *bm = NULL;
    if (block_manager_open(&bm, CURSOR_TEST_FILE, BLOCK_MANAGER_SYNC_NONE) != 0) return;

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

    /* we check previous block */
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

    /* we check previous block */
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

    (void)remove(CURSOR_TEST_FILE);
}

void test_block_manager_cursor_goto_first()
{
    block_manager_t *bm = NULL;
    if (block_manager_open(&bm, CURSOR_TEST_FILE, BLOCK_MANAGER_SYNC_NONE) != 0) return;

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
    (void)remove(CURSOR_TEST_FILE);
}

void test_block_manager_cursor_goto_last()
{
    block_manager_t *bm = NULL;
    if (block_manager_open(&bm, CURSOR_TEST_FILE, BLOCK_MANAGER_SYNC_NONE) != 0) return;

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
    (void)remove(CURSOR_TEST_FILE);
}

void test_block_manager_cursor_has_next()
{
    block_manager_t *bm = NULL;
    if (block_manager_open(&bm, CURSOR_TEST_FILE, BLOCK_MANAGER_SYNC_NONE) != 0) return;

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
    (void)remove(CURSOR_TEST_FILE);
}

void test_block_manager_cursor_has_prev()
{
    block_manager_t *bm = NULL;
    if (block_manager_open(&bm, CURSOR_TEST_FILE, BLOCK_MANAGER_SYNC_NONE) != 0) return;

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
    (void)remove(CURSOR_TEST_FILE);
}

void test_block_manager_cursor_position_checks()
{
    block_manager_t *bm = NULL;
    if (block_manager_open(&bm, CURSOR_TEST_FILE, BLOCK_MANAGER_SYNC_NONE) != 0) return;

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
    (void)remove(CURSOR_TEST_FILE);
}

void test_block_manager_cursor_goto_last_before()
{
    block_manager_t *bm = NULL;
    if (block_manager_open(&bm, CURSOR_TEST_FILE, BLOCK_MANAGER_SYNC_NONE) != 0) return;

    /* we write five blocks -- the first three model an sstable data region and
     * the last two model trailing blocks appended after it */
    uint64_t data_region_end = 0;
    for (int i = 0; i < 5; i++)
    {
        char data[16] = {0};
        snprintf(data, sizeof(data), "block_%d", i);
        block_manager_block_t *block = block_manager_block_create(sizeof(data), data);
        ASSERT_TRUE(block != NULL);
        ASSERT_TRUE(block_manager_block_write(bm, block) >= 0);
        (void)block_manager_block_free(block);

        if (i == 2) ASSERT_EQ(block_manager_get_size(bm, &data_region_end), 0);
    }

    block_manager_cursor_t *cursor;
    if (block_manager_cursor_init(&cursor, bm) != 0)
    {
        (void)block_manager_close(bm);
        return;
    }

    /* anchored at the data-region end, we land on block 2 -- not the trailing
     * block 4 that a whole-file goto_last would reach */
    ASSERT_EQ(block_manager_cursor_goto_last_before(cursor, data_region_end), 0);
    block_manager_block_t *blk = block_manager_cursor_read(cursor);
    ASSERT_TRUE(blk != NULL);
    ASSERT_EQ(memcmp(blk->data, "block_2", 8), 0);
    (void)block_manager_block_free(blk);

    /* whole-file goto_last still reaches the true last block */
    ASSERT_EQ(block_manager_cursor_goto_last(cursor), 0);
    blk = block_manager_cursor_read(cursor);
    ASSERT_TRUE(blk != NULL);
    ASSERT_EQ(memcmp(blk->data, "block_4", 8), 0);
    (void)block_manager_block_free(blk);

    /* backward iteration works after an anchored seek */
    ASSERT_EQ(block_manager_cursor_goto_last_before(cursor, data_region_end), 0);
    ASSERT_EQ(block_manager_cursor_prev(cursor), 0);
    blk = block_manager_cursor_read(cursor);
    ASSERT_TRUE(blk != NULL);
    ASSERT_EQ(memcmp(blk->data, "block_1", 8), 0);
    (void)block_manager_block_free(blk);

    /* an end offset at or below the header has no block to find */
    ASSERT_TRUE(block_manager_cursor_goto_last_before(cursor, BLOCK_MANAGER_HEADER_SIZE) != 0);
    ASSERT_TRUE(block_manager_cursor_goto_last_before(cursor, 0) != 0);
    ASSERT_TRUE(block_manager_cursor_goto_last_before(NULL, data_region_end) != 0);

    (void)block_manager_cursor_free(cursor);
    ASSERT_TRUE(block_manager_close(bm) == 0);
    (void)remove(CURSOR_TEST_FILE);
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

    /* we use stack-allocated cursor */
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

    /* simulate partial write at B leave header intact, zero data+footer.
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

    /* cursor_read(B) must fail-- checksum mismatch on zeroed data */
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

    /* cursor_read must fail-- checksum mismatch */
    block_manager_block_t *block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(block == NULL);

    /* skip must be refused-- footer magic is intact -> genuine corruption */
    ASSERT_EQ(block_manager_cursor_skip_corrupt(cursor), -1);

    printf("  [skip-corrupt] correctly refused to skip genuine corruption at offset %" PRId64 "\n",
           offset);

    block_manager_cursor_free(cursor);
    ASSERT_TRUE(block_manager_close(bm) == 0);
    (void)remove(test_file);
}

void test_cursor_resync_past_hole(void)
{
    const char *test_file = "test_resync_hole.db";
    (void)remove(test_file);

    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, test_file, BLOCK_MANAGER_SYNC_NONE) == 0);

    const char *payload_a = "block_A_before_hole";
    const char *payload_hole = "failed_concurrent_append_victim";
    const char *payload_b = "block_B_after_hole_committed";

    const uint32_t size_a = (uint32_t)(strlen(payload_a) + 1);
    const uint32_t size_hole = (uint32_t)(strlen(payload_hole) + 1);
    const uint32_t size_b = (uint32_t)(strlen(payload_b) + 1);

    const int64_t offset_a = block_manager_write_raw(bm, payload_a, size_a);
    const int64_t offset_hole = block_manager_write_raw(bm, payload_hole, size_hole);
    const int64_t offset_b = block_manager_write_raw(bm, payload_b, size_b);
    ASSERT_TRUE(offset_a >= 0);
    ASSERT_TRUE(offset_hole >= 0);
    ASSERT_TRUE(offset_b >= 0);

    /* simulate a failed concurrent append that reserved space but wrote zero bytes -- zero the
     * whole frame so the size field itself reads 0, the case skip_corrupt cannot advance past.
     * block B sits at a higher offset and is the committed data the hole must not shadow. */
    const size_t hole_len = BLOCK_MANAGER_BLOCK_HEADER_SIZE + size_hole + BLOCK_MANAGER_FOOTER_SIZE;
    uint8_t *zeros = (uint8_t *)calloc(1, hole_len);
    ASSERT_TRUE(zeros != NULL);
    ASSERT_TRUE(pwrite(bm->fd, zeros, hole_len, (off_t)offset_hole) == (ssize_t)hole_len);
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

    /* the hole reads back as a zero size field, and skip_corrupt cannot advance past it */
    block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(block == NULL);
    ASSERT_EQ(block_manager_cursor_skip_corrupt(cursor), -1);

    /* resync finds the next committed block past the hole */
    ASSERT_EQ(block_manager_cursor_resync_past_hole(cursor), 0);

    block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(block != NULL);
    ASSERT_EQ(memcmp(block->data, payload_b, size_b), 0);
    block_manager_block_free(block);

    printf("  [resync] block B at offset %" PRId64
           " recovered after resyncing past a zero hole at offset %" PRId64 "\n",
           offset_b, offset_hole);

    block_manager_cursor_free(cursor);
    ASSERT_TRUE(block_manager_close(bm) == 0);
    (void)remove(test_file);
}

void test_cursor_resync_refuses_data_corruption(void)
{
    const char *test_file = "test_resync_genuine.db";
    (void)remove(test_file);

    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, test_file, BLOCK_MANAGER_SYNC_NONE) == 0);

    const char *payload = "fully_framed_then_corrupted";
    const uint32_t size = (uint32_t)(strlen(payload) + 1);
    const int64_t offset = block_manager_write_raw(bm, payload, size);
    ASSERT_TRUE(offset >= 0);

    /* flip a data byte so the block stays fully framed (valid footer magic) but fails its
     * checksum -- the genuine-corruption case skip_corrupt deliberately halts on */
    const off_t flip = (off_t)offset + BLOCK_MANAGER_BLOCK_HEADER_SIZE + (off_t)(size / 2);
    uint8_t byte_val;
    ASSERT_TRUE(pread(bm->fd, &byte_val, 1, flip) == 1);
    byte_val ^= 0xFFU;
    ASSERT_TRUE(pwrite(bm->fd, &byte_val, 1, flip) == 1);

    ASSERT_TRUE(block_manager_close(bm) == 0);
    ASSERT_TRUE(block_manager_open(&bm, test_file, BLOCK_MANAGER_SYNC_NONE) == 0);

    block_manager_cursor_t *cursor = NULL;
    ASSERT_TRUE(block_manager_cursor_init(&cursor, bm) == 0);

    block_manager_block_t *block = block_manager_cursor_read(cursor);
    ASSERT_TRUE(block == NULL);

    /* the corrupt block has a nonzero size field, so resync refuses it -- the tested policy of
     * halting on real corruption stands untouched */
    ASSERT_EQ(block_manager_cursor_resync_past_hole(cursor), -1);

    printf("  [resync] correctly refused a genuine-corruption block at offset %" PRId64 "\n",
           offset);

    block_manager_cursor_free(cursor);
    ASSERT_TRUE(block_manager_close(bm) == 0);
    (void)remove(test_file);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_block_manager_cursor, tests_passed);
    RUN_TEST(test_block_manager_cursor_goto_first, tests_passed);
    RUN_TEST(test_block_manager_cursor_goto_last, tests_passed);
    RUN_TEST(test_block_manager_cursor_has_next, tests_passed);
    RUN_TEST(test_block_manager_cursor_has_prev, tests_passed);
    RUN_TEST(test_block_manager_cursor_position_checks, tests_passed);
    RUN_TEST(test_block_manager_cursor_goto_last_before, tests_passed);
    RUN_TEST(test_block_manager_cursor_read_and_advance, tests_passed);
    RUN_TEST(test_block_manager_cursor_has_next_exhausted, tests_passed);
    RUN_TEST(test_block_manager_cursor_next_past_eof, tests_passed);
    RUN_TEST(test_block_manager_cursor_goto_invalid, tests_passed);
    RUN_TEST(test_block_manager_cursor_init_stack_direct, tests_passed);
    RUN_TEST(test_cursor_skip_corrupt_partial_write, tests_passed);
    RUN_TEST(test_cursor_skip_corrupt_refuses_data_corruption, tests_passed);
    RUN_TEST(test_cursor_resync_past_hole, tests_passed);
    RUN_TEST(test_cursor_resync_refuses_data_corruption, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
