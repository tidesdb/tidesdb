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
    assert(block_manager_open(&bm, "test.db", 0.2f) == 0);
    assert(bm != NULL);
    assert(bm->file != NULL);
    assert(strcmp(bm->file_path, "test.db") == 0);
    assert(bm->fsync_interval == 0.2f);
    block_manager_close(bm);

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
    block_manager_block_free(block);

    printf(GREEN "test_block_manager_block_create passed\n" RESET);
}

void test_block_manager_block_write()
{
    /* we set up a new block manager */
    block_manager_t *bm;
    if (block_manager_open(&bm, "test.db", 0.2f) != 0) return;

    /* we set up a new block */
    uint64_t size = 10;
    char data[10] = "testdata";
    block_manager_block_t *block = block_manager_block_create(size, data);
    assert(block != NULL); /* we verify that the block was created successfully */

    /* now we write the block to the file */
    assert(block_manager_block_write(bm, block) == 0);

    block_manager_block_free(block);

    /* we close the block manager */
    assert(block_manager_close(bm) == 0);

    /* we remove the file */
    remove("test.db");

    printf(GREEN "test_block_manager_block_write passed\n" RESET);
}

void test_block_manager_block_write_close_reopen_read()
{
    /* we set up a new block manager */
    block_manager_t *bm;
    if (block_manager_open(&bm, "test.db", 0.2f) != 0) return;

    /* we set up a new block */
    uint64_t size = 10;
    char data[10] = "testdata";
    block_manager_block_t *block = block_manager_block_create(size, data);
    assert(block != NULL); /* we verify that the block was created successfully */

    /* now we write the block to the file */
    assert(block_manager_block_write(bm, block) == 0);

    block_manager_block_free(block);

    /* we close the block manager */
    assert(block_manager_close(bm) == 0);

    /* we reopen the block manager */
    if (block_manager_open(&bm, "test.db", 0.2f) != 0) return;

    /* we read the block from the file */
    block = block_manager_block_read(bm);
    assert(block != NULL);

    /* we verify that the block was read correctly */
    assert(block->size == size);
    assert(memcmp(block->data, data, size) == 0);

    block_manager_block_free(block);

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
    if (block_manager_open(&bm, "test.db", 0.2f) != 0) return;

    /* we set up a new block */
    uint64_t size = 10;
    char data[10] = "testdata";
    block_manager_block_t *block = block_manager_block_create(size, data);
    assert(block != NULL); /* we verify that the block was created successfully */

    /* now we write the block to the file */
    assert(block_manager_block_write(bm, block) == 0);

    block_manager_block_free(block);

    /* we truncate the file */
    assert(block_manager_truncate(bm) == 0);

    /* we close the block manager */
    assert(block_manager_close(bm) == 0);

    /* we reopen the block manager */
    if (block_manager_open(&bm, "test.db", 0.2f) != 0) return;

    /* we read the block from the file */
    block = block_manager_block_read(bm);
    assert(block == NULL); /* we expect the block to be NULL */

    /* we close the block manager */
    assert(block_manager_close(bm) == 0);

    /* we remove the file */
    remove("test.db");

    printf(GREEN "test_block_manager_truncate passed\n" RESET);
}

void test_block_manager_cursor()
{
    /* we create a block manager, write a few blocks and verify forward and backward iteration */

    /* we set up a new block manager */
    block_manager_t *bm;
    if (block_manager_open(&bm, "test.db", 0.2f) != 0) return;

    for (int i = 0; i < 3; i++)
    {
        /* we set up a new block */
        uint64_t size = 10;
        char data[10];

        snprintf(data, 10, "testdata%d", i);

        block_manager_block_t *block = block_manager_block_create(size, data);
        assert(block != NULL); /* we verify that the block was created successfully */

        /* now we write the block to the file */
        assert(block_manager_block_write(bm, block) == 0);

        block_manager_block_free(block);
    }

    /* now we create a cursor */
    block_manager_cursor_t *cursor;

    if (block_manager_cursor_init(&cursor, bm) != 0)
    {
        block_manager_close(bm);
        return;
    }

    /* we get first block from cursor should be the first block we wrote */
    block_manager_block_t *read_block = block_manager_cursor_read(cursor);
    if (read_block == NULL)
    {
        block_manager_cursor_free(cursor);
        block_manager_close(bm);
        return;
    }
    assert(read_block->size == 10);
    assert(memcmp(read_block->data, "testdata0", 10) == 0);

    block_manager_block_free(read_block);

    /* we go next */
    assert(block_manager_cursor_next(cursor) == 0);

    /* check next block */
    read_block = block_manager_cursor_read(cursor);
    if (read_block == NULL)
    {
        block_manager_cursor_free(cursor);
        block_manager_close(bm);
        return;
    }

    assert(read_block->size == 10);
    assert(memcmp(read_block->data, "testdata1", 10) == 0);

    block_manager_block_free(read_block);

    /* we go next */
    assert(block_manager_cursor_next(cursor) == 0);

    /* check next block */
    read_block = block_manager_cursor_read(cursor);
    if (read_block == NULL)
    {
        block_manager_cursor_free(cursor);
        block_manager_close(bm);
        return;
    }

    /* we verify that the block was read correctly */
    assert(read_block->size == 10);
    assert(memcmp(read_block->data, "testdata2", 10) == 0);

    block_manager_block_free(read_block);

    /* we go back */
    assert(block_manager_cursor_prev(cursor) == 0);

    /* check previous block */
    read_block = block_manager_cursor_read(cursor);
    if (read_block == NULL)
    {
        block_manager_cursor_free(cursor);
        block_manager_close(bm);
        return;
    }

    /* we verify that the block was read correctly */
    assert(read_block->size == 10);
    assert(memcmp(read_block->data, "testdata1", 10) == 0);

    block_manager_block_free(read_block);

    /* we go back */
    assert(block_manager_cursor_prev(cursor) == 0);

    /* check previous block */
    read_block = block_manager_cursor_read(cursor);
    if (read_block == NULL)
    {
        block_manager_cursor_free(cursor);
        block_manager_close(bm);
        return;
    }

    /* we verify that the block was read correctly */
    assert(read_block->size == 10);
    assert(memcmp(read_block->data, "testdata0", 10) == 0);

    block_manager_block_free(read_block);

    /* we free the cursor */
    block_manager_cursor_free(cursor);

    /* we close the block manager */
    assert(block_manager_close(bm) == 0);

    /* we remove the file */
    remove("test.db");

    printf(GREEN "test_block_manager_cursor passed\n" RESET);
}

void example()
{
    block_manager_t *bm;
    if (block_manager_open(&bm, "test.db", 0.2f) != 0)
    {
        fprintf(stderr, "Failed to open block manager\n");
        return;
    }

    for (int i = 0; i < 3; i++)
    {
        uint64_t size = 10;
        char data[10];
        snprintf(data, 10, "testdata%d", i);

        block_manager_block_t *block = block_manager_block_create(size, data);
        assert(block != NULL);

        assert(block_manager_block_write(bm, block) == 0);
        block_manager_block_free(block);
    }

    block_manager_cursor_t *cursor;
    if (block_manager_cursor_init(&cursor, bm) != 0)
    {
        fprintf(stderr, "Failed to initialize cursor\n");
        block_manager_close(bm);
        return;
    }

    printf("Iterating forwards:\n");
    block_manager_block_t *read_block;
    while ((read_block = block_manager_cursor_read(cursor)) != NULL)
    {
        printf("Block data: %.*s\n", (int)read_block->size, (char *)read_block->data);
        block_manager_block_free(read_block);
        if (block_manager_cursor_next(cursor) != 0) break;
    }

    printf("Iterating backwards:\n");
    while (block_manager_cursor_prev(cursor) == 0)
    {
        read_block = block_manager_cursor_read(cursor);
        if (read_block == NULL) break;
        printf("Block data: %.*s\n", (int)read_block->size, (char *)read_block->data);
        block_manager_block_free(read_block);
    }

    block_manager_cursor_free(cursor);
    assert(block_manager_close(bm) == 0);
    remove("test.db");
}

int main(void)
{
    test_block_manager_open();
    test_block_manager_block_create();
    test_block_manager_block_write();
    test_block_manager_block_write_close_reopen_read();
    test_block_manager_truncate();
    test_block_manager_cursor();

    return 0;
}