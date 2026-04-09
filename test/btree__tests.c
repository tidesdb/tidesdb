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

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/btree.h"
#include "../src/compress.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_BTREE_FILE "test_btree.db"

void test_btree_builder_new()
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, TEST_BTREE_FILE, BLOCK_MANAGER_SYNC_NONE) == 0);

    btree_config_t config = {.target_node_size = BTREE_DEFAULT_NODE_SIZE,
                             .value_threshold = 512,
                             .comparator = NULL,
                             .comparator_ctx = NULL,
                             .cmp_type = BTREE_CMP_MEMCMP};

    btree_builder_t *builder = NULL;
    ASSERT_TRUE(btree_builder_new(&builder, bm, &config) == 0);
    ASSERT_TRUE(builder != NULL);

    btree_builder_free(builder);
    (void)block_manager_close(bm);
    (void)remove(TEST_BTREE_FILE);
}

void test_btree_builder_add_single()
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, TEST_BTREE_FILE, BLOCK_MANAGER_SYNC_NONE) == 0);

    btree_config_t config = {.target_node_size = BTREE_DEFAULT_NODE_SIZE,
                             .value_threshold = 512,
                             .comparator = NULL,
                             .comparator_ctx = NULL,
                             .cmp_type = BTREE_CMP_MEMCMP};

    btree_builder_t *builder = NULL;
    ASSERT_TRUE(btree_builder_new(&builder, bm, &config) == 0);

    uint8_t key[] = "testkey";
    uint8_t value[] = "testvalue";
    ASSERT_TRUE(btree_builder_add(builder, key, sizeof(key), value, sizeof(value), 0, 1, 0, 0) ==
                0);

    btree_t *tree = NULL;
    ASSERT_TRUE(btree_builder_finish(builder, &tree) == 0);
    ASSERT_TRUE(tree != NULL);
    ASSERT_EQ(tree->entry_count, 1);

    btree_free(tree);
    btree_builder_free(builder);
    (void)block_manager_close(bm);
    (void)remove(TEST_BTREE_FILE);
}

void test_btree_builder_add_multiple()
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, TEST_BTREE_FILE, BLOCK_MANAGER_SYNC_NONE) == 0);

    btree_config_t config = {.target_node_size = BTREE_DEFAULT_NODE_SIZE,
                             .value_threshold = 512,
                             .comparator = NULL,
                             .comparator_ctx = NULL,
                             .cmp_type = BTREE_CMP_MEMCMP};

    btree_builder_t *builder = NULL;
    ASSERT_TRUE(btree_builder_new(&builder, bm, &config) == 0);

    for (int i = 0; i < 100; i++)
    {
        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "key%05d", i);
        snprintf(value, sizeof(value), "value%05d", i);
        ASSERT_TRUE(btree_builder_add(builder, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0, (uint64_t)i, 0, 0) == 0);
    }

    btree_t *tree = NULL;
    ASSERT_TRUE(btree_builder_finish(builder, &tree) == 0);
    ASSERT_TRUE(tree != NULL);
    ASSERT_EQ(tree->entry_count, 100);

    printf("\n--- Multiple Entries Tree Structure ---\n");
    btree_print_tree(tree);

    btree_free(tree);
    btree_builder_free(builder);
    (void)block_manager_close(bm);
    (void)remove(TEST_BTREE_FILE);
}

void test_btree_get()
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, TEST_BTREE_FILE, BLOCK_MANAGER_SYNC_NONE) == 0);

    btree_config_t config = {.target_node_size = BTREE_DEFAULT_NODE_SIZE,
                             .value_threshold = 512,
                             .comparator = NULL,
                             .comparator_ctx = NULL,
                             .cmp_type = BTREE_CMP_MEMCMP};

    btree_builder_t *builder = NULL;
    ASSERT_TRUE(btree_builder_new(&builder, bm, &config) == 0);

    for (int i = 0; i < 50; i++)
    {
        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "key%05d", i);
        snprintf(value, sizeof(value), "value%05d", i);
        ASSERT_TRUE(btree_builder_add(builder, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0, (uint64_t)i, 0, 0) == 0);
    }

    btree_t *tree = NULL;
    ASSERT_TRUE(btree_builder_finish(builder, &tree) == 0);

    uint8_t *value = NULL;
    size_t value_size = 0;
    uint64_t vlog_offset = 0;
    uint64_t seq = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;

    char search_key[32];
    snprintf(search_key, sizeof(search_key), "key%05d", 25);
    ASSERT_TRUE(btree_get(tree, (uint8_t *)search_key, strlen(search_key) + 1, &value, &value_size,
                          &vlog_offset, &seq, &ttl, &deleted) == 0);
    ASSERT_TRUE(value != NULL);

    char expected_value[64];
    snprintf(expected_value, sizeof(expected_value), "value%05d", 25);
    ASSERT_EQ(strcmp((char *)value, expected_value), 0);
    ASSERT_EQ(seq, 25);
    free(value);

    value = NULL;
    ASSERT_TRUE(btree_get(tree, (uint8_t *)"nonexistent", 12, &value, &value_size, &vlog_offset,
                          &seq, &ttl, &deleted) != 0);

    btree_free(tree);
    btree_builder_free(builder);
    (void)block_manager_close(bm);
    (void)remove(TEST_BTREE_FILE);
}

void test_btree_cursor_forward()
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, TEST_BTREE_FILE, BLOCK_MANAGER_SYNC_NONE) == 0);

    btree_config_t config = {.target_node_size = BTREE_DEFAULT_NODE_SIZE,
                             .value_threshold = 512,
                             .comparator = NULL,
                             .comparator_ctx = NULL,
                             .cmp_type = BTREE_CMP_MEMCMP};

    btree_builder_t *builder = NULL;
    ASSERT_TRUE(btree_builder_new(&builder, bm, &config) == 0);

    for (int i = 0; i < 20; i++)
    {
        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "key%05d", i);
        snprintf(value, sizeof(value), "value%05d", i);
        ASSERT_TRUE(btree_builder_add(builder, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0, (uint64_t)i, 0, 0) == 0);
    }

    btree_t *tree = NULL;
    ASSERT_TRUE(btree_builder_finish(builder, &tree) == 0);

    btree_cursor_t *cursor = NULL;
    ASSERT_TRUE(btree_cursor_init(&cursor, tree) == 0);
    ASSERT_TRUE(cursor != NULL);

    int count = 0;
    while (btree_cursor_valid(cursor))
    {
        uint8_t *key = NULL;
        size_t key_size = 0;
        uint8_t *value = NULL;
        size_t value_size = 0;
        uint64_t vlog_offset = 0;
        uint64_t seq = 0;
        int64_t ttl = 0;
        uint8_t deleted = 0;

        ASSERT_TRUE(btree_cursor_get(cursor, &key, &key_size, &value, &value_size, &vlog_offset,
                                     &seq, &ttl, &deleted) == 0);
        ASSERT_TRUE(key != NULL);

        char expected_key[32];
        snprintf(expected_key, sizeof(expected_key), "key%05d", count);
        ASSERT_EQ(strcmp((char *)key, expected_key), 0);

        count++;
        btree_cursor_next(cursor);
    }

    ASSERT_EQ(count, 20);

    btree_cursor_free(cursor);
    btree_free(tree);
    btree_builder_free(builder);
    (void)block_manager_close(bm);
    (void)remove(TEST_BTREE_FILE);
}

void test_btree_cursor_backward()
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, TEST_BTREE_FILE, BLOCK_MANAGER_SYNC_NONE) == 0);

    btree_config_t config = {.target_node_size = BTREE_DEFAULT_NODE_SIZE,
                             .value_threshold = 512,
                             .comparator = NULL,
                             .comparator_ctx = NULL,
                             .cmp_type = BTREE_CMP_MEMCMP};

    btree_builder_t *builder = NULL;
    ASSERT_TRUE(btree_builder_new(&builder, bm, &config) == 0);

    for (int i = 0; i < 20; i++)
    {
        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "key%05d", i);
        snprintf(value, sizeof(value), "value%05d", i);
        ASSERT_TRUE(btree_builder_add(builder, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0, (uint64_t)i, 0, 0) == 0);
    }

    btree_t *tree = NULL;
    ASSERT_TRUE(btree_builder_finish(builder, &tree) == 0);

    btree_cursor_t *cursor = NULL;
    ASSERT_TRUE(btree_cursor_init(&cursor, tree) == 0);
    ASSERT_TRUE(btree_cursor_goto_last(cursor) == 0);
    ASSERT_TRUE(cursor != NULL);

    int count = 19;
    while (btree_cursor_valid(cursor))
    {
        uint8_t *key = NULL;
        size_t key_size = 0;
        uint8_t *value = NULL;
        size_t value_size = 0;
        uint64_t vlog_offset = 0;
        uint64_t seq = 0;
        int64_t ttl = 0;
        uint8_t deleted = 0;

        ASSERT_TRUE(btree_cursor_get(cursor, &key, &key_size, &value, &value_size, &vlog_offset,
                                     &seq, &ttl, &deleted) == 0);
        ASSERT_TRUE(key != NULL);

        char expected_key[32];
        snprintf(expected_key, sizeof(expected_key), "key%05d", count);
        ASSERT_EQ(strcmp((char *)key, expected_key), 0);

        count--;
        btree_cursor_prev(cursor);
    }

    ASSERT_EQ(count, -1);

    btree_cursor_free(cursor);
    btree_free(tree);
    btree_builder_free(builder);
    (void)block_manager_close(bm);
    (void)remove(TEST_BTREE_FILE);
}

void test_btree_cursor_seek()
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, TEST_BTREE_FILE, BLOCK_MANAGER_SYNC_NONE) == 0);

    btree_config_t config = {.target_node_size = BTREE_DEFAULT_NODE_SIZE,
                             .value_threshold = 512,
                             .comparator = NULL,
                             .comparator_ctx = NULL,
                             .cmp_type = BTREE_CMP_MEMCMP};

    btree_builder_t *builder = NULL;
    ASSERT_TRUE(btree_builder_new(&builder, bm, &config) == 0);

    for (int i = 0; i < 100; i++)
    {
        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "key%05d", i);
        snprintf(value, sizeof(value), "value%05d", i);
        ASSERT_TRUE(btree_builder_add(builder, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0, (uint64_t)i, 0, 0) == 0);
    }

    btree_t *tree = NULL;
    ASSERT_TRUE(btree_builder_finish(builder, &tree) == 0);

    btree_cursor_t *cursor = NULL;
    ASSERT_TRUE(btree_cursor_init(&cursor, tree) == 0);

    char seek_key[32];
    snprintf(seek_key, sizeof(seek_key), "key%05d", 50);
    ASSERT_TRUE(btree_cursor_seek(cursor, (uint8_t *)seek_key, strlen(seek_key) + 1) == 0);
    ASSERT_TRUE(btree_cursor_valid(cursor));

    uint8_t *key = NULL;
    size_t key_size = 0;
    uint8_t *value = NULL;
    size_t value_size = 0;
    uint64_t vlog_offset = 0;
    uint64_t seq = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;

    ASSERT_TRUE(btree_cursor_get(cursor, &key, &key_size, &value, &value_size, &vlog_offset, &seq,
                                 &ttl, &deleted) == 0);
    ASSERT_EQ(strcmp((char *)key, seek_key), 0);

    btree_cursor_free(cursor);
    btree_free(tree);
    btree_builder_free(builder);
    (void)block_manager_close(bm);
    (void)remove(TEST_BTREE_FILE);
}

void test_btree_min_max_keys()
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, TEST_BTREE_FILE, BLOCK_MANAGER_SYNC_NONE) == 0);

    btree_config_t config = {.target_node_size = BTREE_DEFAULT_NODE_SIZE,
                             .value_threshold = 512,
                             .comparator = NULL,
                             .comparator_ctx = NULL,
                             .cmp_type = BTREE_CMP_MEMCMP};

    btree_builder_t *builder = NULL;
    ASSERT_TRUE(btree_builder_new(&builder, bm, &config) == 0);

    for (int i = 0; i < 50; i++)
    {
        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "key%05d", i);
        snprintf(value, sizeof(value), "value%05d", i);
        ASSERT_TRUE(btree_builder_add(builder, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0, (uint64_t)i, 0, 0) == 0);
    }

    btree_t *tree = NULL;
    ASSERT_TRUE(btree_builder_finish(builder, &tree) == 0);

    uint8_t *min_key = NULL;
    size_t min_key_size = 0;
    ASSERT_TRUE(btree_get_min_key(tree, &min_key, &min_key_size) == 0);
    ASSERT_EQ(strcmp((char *)min_key, "key00000"), 0);
    free(min_key);

    uint8_t *max_key = NULL;
    size_t max_key_size = 0;
    ASSERT_TRUE(btree_get_max_key(tree, &max_key, &max_key_size) == 0);
    ASSERT_EQ(strcmp((char *)max_key, "key00049"), 0);
    free(max_key);

    btree_free(tree);
    btree_builder_free(builder);
    (void)block_manager_close(bm);
    (void)remove(TEST_BTREE_FILE);
}

void test_btree_max_seq()
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, TEST_BTREE_FILE, BLOCK_MANAGER_SYNC_NONE) == 0);

    btree_config_t config = {.target_node_size = BTREE_DEFAULT_NODE_SIZE,
                             .value_threshold = 512,
                             .comparator = NULL,
                             .comparator_ctx = NULL,
                             .cmp_type = BTREE_CMP_MEMCMP};

    btree_builder_t *builder = NULL;
    ASSERT_TRUE(btree_builder_new(&builder, bm, &config) == 0);

    for (int i = 0; i < 10; i++)
    {
        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "key%05d", i);
        snprintf(value, sizeof(value), "value%05d", i);
        ASSERT_TRUE(btree_builder_add(builder, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0, (uint64_t)(i * 10), 0, 0) == 0);
    }

    btree_t *tree = NULL;
    ASSERT_TRUE(btree_builder_finish(builder, &tree) == 0);

    uint64_t max_seq = btree_get_max_seq(tree);
    ASSERT_EQ(max_seq, 90);

    btree_free(tree);
    btree_builder_free(builder);
    (void)block_manager_close(bm);
    (void)remove(TEST_BTREE_FILE);
}

void test_btree_open_existing()
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, TEST_BTREE_FILE, BLOCK_MANAGER_SYNC_NONE) == 0);

    btree_config_t config = {.target_node_size = BTREE_DEFAULT_NODE_SIZE,
                             .value_threshold = 512,
                             .comparator = NULL,
                             .comparator_ctx = NULL,
                             .cmp_type = BTREE_CMP_MEMCMP};

    btree_builder_t *builder = NULL;
    ASSERT_TRUE(btree_builder_new(&builder, bm, &config) == 0);

    for (int i = 0; i < 30; i++)
    {
        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "key%05d", i);
        snprintf(value, sizeof(value), "value%05d", i);
        ASSERT_TRUE(btree_builder_add(builder, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0, (uint64_t)i, 0, 0) == 0);
    }

    btree_t *tree = NULL;
    ASSERT_TRUE(btree_builder_finish(builder, &tree) == 0);
    ASSERT_EQ(tree->entry_count, 30);

    int64_t root_offset = tree->root_offset;
    int64_t first_leaf_offset = tree->first_leaf_offset;
    int64_t last_leaf_offset = tree->last_leaf_offset;

    btree_free(tree);
    btree_builder_free(builder);
    (void)block_manager_close(bm);

    ASSERT_TRUE(block_manager_open(&bm, TEST_BTREE_FILE, BLOCK_MANAGER_SYNC_NONE) == 0);

    btree_t *reopened = NULL;
    ASSERT_TRUE(
        btree_open(&reopened, bm, &config, root_offset, first_leaf_offset, last_leaf_offset) == 0);
    ASSERT_TRUE(reopened != NULL);

    char search_key[32];
    snprintf(search_key, sizeof(search_key), "key%05d", 15);

    uint8_t *value = NULL;
    size_t value_size = 0;
    uint64_t vlog_offset = 0;
    uint64_t seq = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;

    ASSERT_TRUE(btree_get(reopened, (uint8_t *)search_key, strlen(search_key) + 1, &value,
                          &value_size, &vlog_offset, &seq, &ttl, &deleted) == 0);
    ASSERT_TRUE(value != NULL);

    char expected_value[64];
    snprintf(expected_value, sizeof(expected_value), "value%05d", 15);
    ASSERT_EQ(strcmp((char *)value, expected_value), 0);
    free(value);

    btree_free(reopened);
    (void)block_manager_close(bm);
    (void)remove(TEST_BTREE_FILE);
}

void test_btree_tombstone()
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, TEST_BTREE_FILE, BLOCK_MANAGER_SYNC_NONE) == 0);

    btree_config_t config = {.target_node_size = BTREE_DEFAULT_NODE_SIZE,
                             .value_threshold = 512,
                             .comparator = NULL,
                             .comparator_ctx = NULL,
                             .cmp_type = BTREE_CMP_MEMCMP};

    btree_builder_t *builder = NULL;
    ASSERT_TRUE(btree_builder_new(&builder, bm, &config) == 0);

    uint8_t key1[] = "key1";
    uint8_t value1[] = "value1";
    ASSERT_TRUE(
        btree_builder_add(builder, key1, sizeof(key1), value1, sizeof(value1), 0, 1, 0, 0) == 0);

    uint8_t key2[] = "key2";
    ASSERT_TRUE(btree_builder_add(builder, key2, sizeof(key2), NULL, 0, 0, 2, 0, 1) == 0);

    btree_t *tree = NULL;
    ASSERT_TRUE(btree_builder_finish(builder, &tree) == 0);

    uint8_t *value = NULL;
    size_t value_size = 0;
    uint64_t vlog_offset = 0;
    uint64_t seq = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;

    ASSERT_TRUE(btree_get(tree, key2, sizeof(key2), &value, &value_size, &vlog_offset, &seq, &ttl,
                          &deleted) == 0);
    ASSERT_EQ(deleted, 1);

    btree_free(tree);
    btree_builder_free(builder);
    (void)block_manager_close(bm);
    (void)remove(TEST_BTREE_FILE);
}

void test_btree_large_dataset()
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, TEST_BTREE_FILE, BLOCK_MANAGER_SYNC_NONE) == 0);

    btree_config_t config = {.target_node_size = 4096, /* smaller node size to force more nodes */
                             .value_threshold = 512,
                             .comparator = NULL,
                             .comparator_ctx = NULL,
                             .cmp_type = BTREE_CMP_MEMCMP};

    btree_builder_t *builder = NULL;
    ASSERT_TRUE(btree_builder_new(&builder, bm, &config) == 0);

    int num_entries = 1000;
    for (int i = 0; i < num_entries; i++)
    {
        char key[32];
        char value[128];
        snprintf(key, sizeof(key), "key%08d", i);
        snprintf(value, sizeof(value), "value%08d_with_some_extra_data_to_make_it_larger", i);
        ASSERT_TRUE(btree_builder_add(builder, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0, (uint64_t)i, 0, 0) == 0);
    }

    btree_t *tree = NULL;
    ASSERT_TRUE(btree_builder_finish(builder, &tree) == 0);
    ASSERT_EQ(tree->entry_count, (uint64_t)num_entries);
    ASSERT_TRUE(tree->node_count > 1); /* should have multiple nodes */

    printf("\n--- Large Dataset Tree Structure ---\n");
    btree_print_tree(tree);

    for (int i = 0; i < 10; i++)
    {
        int idx = rand() % num_entries;
        char search_key[32];
        snprintf(search_key, sizeof(search_key), "key%08d", idx);

        uint8_t *value = NULL;
        size_t value_size = 0;
        uint64_t vlog_offset = 0;
        uint64_t seq = 0;
        int64_t ttl = 0;
        uint8_t deleted = 0;

        ASSERT_TRUE(btree_get(tree, (uint8_t *)search_key, strlen(search_key) + 1, &value,
                              &value_size, &vlog_offset, &seq, &ttl, &deleted) == 0);
        ASSERT_TRUE(value != NULL);
        free(value);
    }

    /* we verify cursor iteration count */
    btree_cursor_t *cursor = NULL;
    ASSERT_TRUE(btree_cursor_init(&cursor, tree) == 0);

    int count = 0;
    while (btree_cursor_valid(cursor))
    {
        count++;
        btree_cursor_next(cursor);
    }
    ASSERT_EQ(count, num_entries);

    btree_cursor_free(cursor);
    btree_free(tree);
    btree_builder_free(builder);
    (void)block_manager_close(bm);
    (void)remove(TEST_BTREE_FILE);
}

void test_btree_empty_tree()
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, TEST_BTREE_FILE, BLOCK_MANAGER_SYNC_NONE) == 0);

    btree_config_t config = {.target_node_size = BTREE_DEFAULT_NODE_SIZE,
                             .value_threshold = 512,
                             .comparator = NULL,
                             .comparator_ctx = NULL,
                             .cmp_type = BTREE_CMP_MEMCMP};

    btree_builder_t *builder = NULL;
    ASSERT_TRUE(btree_builder_new(&builder, bm, &config) == 0);

    btree_t *tree = NULL;
    ASSERT_TRUE(btree_builder_finish(builder, &tree) == 0);
    ASSERT_EQ(tree->entry_count, 0);

    btree_cursor_t *cursor = NULL;
    ASSERT_TRUE(btree_cursor_init(&cursor, tree) != 0 || !btree_cursor_valid(cursor));
    if (cursor) btree_cursor_free(cursor);

    uint8_t *value = NULL;
    size_t value_size = 0;
    uint64_t vlog_offset = 0;
    uint64_t seq = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;
    ASSERT_TRUE(btree_get(tree, (uint8_t *)"key", 4, &value, &value_size, &vlog_offset, &seq, &ttl,
                          &deleted) != 0);

    btree_free(tree);
    btree_builder_free(builder);
    (void)block_manager_close(bm);
    (void)remove(TEST_BTREE_FILE);
}

void test_btree_single_entry()
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, TEST_BTREE_FILE, BLOCK_MANAGER_SYNC_NONE) == 0);

    btree_config_t config = {.target_node_size = BTREE_DEFAULT_NODE_SIZE,
                             .value_threshold = 512,
                             .comparator = NULL,
                             .comparator_ctx = NULL,
                             .cmp_type = BTREE_CMP_MEMCMP};

    btree_builder_t *builder = NULL;
    ASSERT_TRUE(btree_builder_new(&builder, bm, &config) == 0);

    uint8_t key[] = "only_key";
    uint8_t value[] = "only_value";
    ASSERT_TRUE(btree_builder_add(builder, key, sizeof(key), value, sizeof(value), 0, 42, 0, 0) ==
                0);

    btree_t *tree = NULL;
    ASSERT_TRUE(btree_builder_finish(builder, &tree) == 0);
    ASSERT_EQ(tree->entry_count, 1);

    btree_cursor_t *cursor = NULL;
    ASSERT_TRUE(btree_cursor_init(&cursor, tree) == 0);
    ASSERT_TRUE(btree_cursor_valid(cursor));

    btree_cursor_next(cursor);
    ASSERT_TRUE(!btree_cursor_valid(cursor));

    btree_cursor_free(cursor);
    btree_free(tree);
    btree_builder_free(builder);
    (void)block_manager_close(bm);
    (void)remove(TEST_BTREE_FILE);
}

void test_btree_duplicate_keys()
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, TEST_BTREE_FILE, BLOCK_MANAGER_SYNC_NONE) == 0);

    btree_config_t config = {.target_node_size = BTREE_DEFAULT_NODE_SIZE,
                             .value_threshold = 512,
                             .comparator = NULL,
                             .comparator_ctx = NULL,
                             .cmp_type = BTREE_CMP_MEMCMP};

    btree_builder_t *builder = NULL;
    ASSERT_TRUE(btree_builder_new(&builder, bm, &config) == 0);

    uint8_t key[] = "same_key";
    uint8_t value1[] = "value1";
    uint8_t value2[] = "value2";
    uint8_t value3[] = "value3";
    ASSERT_TRUE(btree_builder_add(builder, key, sizeof(key), value1, sizeof(value1), 0, 1, 0, 0) ==
                0);
    ASSERT_TRUE(btree_builder_add(builder, key, sizeof(key), value2, sizeof(value2), 0, 2, 0, 0) ==
                0);
    ASSERT_TRUE(btree_builder_add(builder, key, sizeof(key), value3, sizeof(value3), 0, 3, 0, 0) ==
                0);

    btree_t *tree = NULL;
    ASSERT_TRUE(btree_builder_finish(builder, &tree) == 0);
    ASSERT_EQ(tree->entry_count, 3);

    btree_cursor_t *cursor = NULL;
    ASSERT_TRUE(btree_cursor_init(&cursor, tree) == 0);

    int count = 0;
    while (btree_cursor_valid(cursor))
    {
        count++;
        btree_cursor_next(cursor);
    }
    ASSERT_EQ(count, 3);

    btree_cursor_free(cursor);
    btree_free(tree);
    btree_builder_free(builder);
    (void)block_manager_close(bm);
    (void)remove(TEST_BTREE_FILE);
}

void test_btree_large_keys_values()
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, TEST_BTREE_FILE, BLOCK_MANAGER_SYNC_NONE) == 0);

    btree_config_t config = {.target_node_size = BTREE_DEFAULT_NODE_SIZE,
                             .value_threshold = 512,
                             .comparator = NULL,
                             .comparator_ctx = NULL,
                             .cmp_type = BTREE_CMP_MEMCMP};

    btree_builder_t *builder = NULL;
    ASSERT_TRUE(btree_builder_new(&builder, bm, &config) == 0);

    size_t large_key_size = 1024;
    size_t large_value_size = 4096;
    uint8_t *large_key = malloc(large_key_size);
    uint8_t *large_value = malloc(large_value_size);

    memset(large_key, 'K', large_key_size - 1);
    large_key[large_key_size - 1] = '\0';
    memset(large_value, 'V', large_value_size - 1);
    large_value[large_value_size - 1] = '\0';

    ASSERT_TRUE(btree_builder_add(builder, large_key, large_key_size, large_value, large_value_size,
                                  0, 1, 0, 0) == 0);

    btree_t *tree = NULL;
    ASSERT_TRUE(btree_builder_finish(builder, &tree) == 0);
    ASSERT_EQ(tree->entry_count, 1);

    /* we verify we can retrieve the large value */
    uint8_t *retrieved_value = NULL;
    size_t retrieved_size = 0;
    uint64_t vlog_offset = 0;
    uint64_t seq = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;

    ASSERT_TRUE(btree_get(tree, large_key, large_key_size, &retrieved_value, &retrieved_size,
                          &vlog_offset, &seq, &ttl, &deleted) == 0);
    ASSERT_EQ(retrieved_size, large_value_size);
    ASSERT_EQ(memcmp(retrieved_value, large_value, large_value_size), 0);

    free(retrieved_value);
    free(large_key);
    free(large_value);
    btree_free(tree);
    btree_builder_free(builder);
    (void)block_manager_close(bm);
    (void)remove(TEST_BTREE_FILE);
}

void test_btree_seek_edge_cases()
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, TEST_BTREE_FILE, BLOCK_MANAGER_SYNC_NONE) == 0);

    btree_config_t config = {.target_node_size = BTREE_DEFAULT_NODE_SIZE,
                             .value_threshold = 512,
                             .comparator = NULL,
                             .comparator_ctx = NULL,
                             .cmp_type = BTREE_CMP_MEMCMP};

    btree_builder_t *builder = NULL;
    ASSERT_TRUE(btree_builder_new(&builder, bm, &config) == 0);

    /* we add keys with gaps: key10, key20, key30, key40, key50 */
    for (int i = 1; i <= 5; i++)
    {
        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "key%02d", i * 10);
        snprintf(value, sizeof(value), "value%02d", i * 10);
        ASSERT_TRUE(btree_builder_add(builder, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0, (uint64_t)i, 0, 0) == 0);
    }

    btree_t *tree = NULL;
    ASSERT_TRUE(btree_builder_finish(builder, &tree) == 0);

    btree_cursor_t *cursor = NULL;
    ASSERT_TRUE(btree_cursor_init(&cursor, tree) == 0);

    /* we seek to exact key */
    ASSERT_TRUE(btree_cursor_seek(cursor, (uint8_t *)"key30", 6) == 0);
    ASSERT_TRUE(btree_cursor_valid(cursor));

    /* we seek to key before first -- should position at first */
    ASSERT_TRUE(btree_cursor_seek(cursor, (uint8_t *)"key05", 6) == 0);
    ASSERT_TRUE(btree_cursor_valid(cursor));

    /* we seek to key between existing keys -- should position at next >= */
    ASSERT_TRUE(btree_cursor_seek(cursor, (uint8_t *)"key25", 6) == 0);
    ASSERT_TRUE(btree_cursor_valid(cursor));

    btree_cursor_free(cursor);
    btree_free(tree);
    btree_builder_free(builder);
    (void)block_manager_close(bm);
    (void)remove(TEST_BTREE_FILE);
}

void test_btree_arena(void)
{
    /* create default arena */
    btree_arena_t *arena = btree_arena_create();
    ASSERT_TRUE(arena != NULL);
    ASSERT_TRUE(arena->total_allocated == BTREE_ARENA_BLOCK_SIZE);

    /* alloc small chunks */
    void *p1 = btree_arena_alloc(arena, 16);
    ASSERT_TRUE(p1 != NULL);

    void *p2 = btree_arena_alloc(arena, 128);
    ASSERT_TRUE(p2 != NULL);
    ASSERT_TRUE(p2 != p1);

    /* reset and reuse */
    btree_arena_reset(arena);
    void *p3 = btree_arena_alloc(arena, 16);
    ASSERT_TRUE(p3 != NULL);

    btree_arena_destroy(arena);

    /* create sized arena */
    btree_arena_t *sized = btree_arena_create_sized(1024);
    ASSERT_TRUE(sized != NULL);
    ASSERT_TRUE(sized->total_allocated == 1024);

    void *sp = btree_arena_alloc(sized, 512);
    ASSERT_TRUE(sp != NULL);

    btree_arena_destroy(sized);

    /* sized arena with value below minimum gets clamped */
    btree_arena_t *tiny = btree_arena_create_sized(1);
    ASSERT_TRUE(tiny != NULL);
    ASSERT_TRUE(tiny->total_allocated >= BTREE_ARENA_MIN_BLOCK_SIZE);

    btree_arena_destroy(tiny);

    /* alloc larger than block size forces new block */
    arena = btree_arena_create();
    ASSERT_TRUE(arena != NULL);
    void *big = btree_arena_alloc(arena, BTREE_ARENA_BLOCK_SIZE + 1024);
    ASSERT_TRUE(big != NULL);

    btree_arena_destroy(arena);

    /* NULL and zero-size edge cases */
    ASSERT_TRUE(btree_arena_alloc(NULL, 16) == NULL);
    arena = btree_arena_create();
    ASSERT_TRUE(btree_arena_alloc(arena, 0) == NULL);
    btree_arena_destroy(arena);

    /* destroy/reset NULL should not crash */
    btree_arena_destroy(NULL);
    btree_arena_reset(NULL);
}

void test_btree_comparator_string(void)
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, TEST_BTREE_FILE, BLOCK_MANAGER_SYNC_NONE) == 0);

    btree_config_t config = {.target_node_size = BTREE_DEFAULT_NODE_SIZE,
                             .value_threshold = 512,
                             .comparator = btree_comparator_string,
                             .comparator_ctx = NULL,
                             .cmp_type = BTREE_CMP_STRING};

    btree_builder_t *builder = NULL;
    ASSERT_TRUE(btree_builder_new(&builder, bm, &config) == 0);

    const char *keys[] = {"apple", "banana", "cherry", "date", "elderberry"};
    for (int i = 0; i < 5; i++)
    {
        char value[32];
        snprintf(value, sizeof(value), "val_%s", keys[i]);
        ASSERT_TRUE(btree_builder_add(builder, (uint8_t *)keys[i], strlen(keys[i]) + 1,
                                      (uint8_t *)value, strlen(value) + 1, 0, (uint64_t)i, 0,
                                      0) == 0);
    }

    btree_t *tree = NULL;
    ASSERT_TRUE(btree_builder_finish(builder, &tree) == 0);
    ASSERT_EQ(tree->entry_count, 5);

    /* lookup by string key */
    uint8_t *value = NULL;
    size_t value_size = 0;
    uint64_t vlog_offset = 0, seq = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;

    ASSERT_TRUE(btree_get(tree, (uint8_t *)"cherry", 7, &value, &value_size, &vlog_offset, &seq,
                          &ttl, &deleted) == 0);
    ASSERT_EQ(strcmp((char *)value, "val_cherry"), 0);
    free(value);

    ASSERT_TRUE(btree_get(tree, (uint8_t *)"nonexistent", 12, &value, &value_size, &vlog_offset,
                          &seq, &ttl, &deleted) != 0);

    btree_free(tree);
    btree_builder_free(builder);
    (void)block_manager_close(bm);
    (void)remove(TEST_BTREE_FILE);
}

void test_btree_comparator_numeric(void)
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, TEST_BTREE_FILE, BLOCK_MANAGER_SYNC_NONE) == 0);

    btree_config_t config = {.target_node_size = BTREE_DEFAULT_NODE_SIZE,
                             .value_threshold = 512,
                             .comparator = btree_comparator_numeric,
                             .comparator_ctx = NULL,
                             .cmp_type = BTREE_CMP_NUMERIC};

    btree_builder_t *builder = NULL;
    ASSERT_TRUE(btree_builder_new(&builder, bm, &config) == 0);

    /* we add 8-byte numeric keys in sorted order */
    for (uint64_t i = 0; i < 20; i++)
    {
        uint64_t key = i * 10;
        char value[32];
        snprintf(value, sizeof(value), "num_%" PRIu64, key);
        ASSERT_TRUE(btree_builder_add(builder, (uint8_t *)&key, sizeof(key), (uint8_t *)value,
                                      strlen(value) + 1, 0, i, 0, 0) == 0);
    }

    btree_t *tree = NULL;
    ASSERT_TRUE(btree_builder_finish(builder, &tree) == 0);
    ASSERT_EQ(tree->entry_count, 20);

    /* lookup by numeric key */
    uint64_t search_key = 50;
    uint8_t *value = NULL;
    size_t value_size = 0;
    uint64_t vlog_offset = 0, seq = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;

    ASSERT_TRUE(btree_get(tree, (uint8_t *)&search_key, sizeof(search_key), &value, &value_size,
                          &vlog_offset, &seq, &ttl, &deleted) == 0);
    ASSERT_EQ(strcmp((char *)value, "num_50"), 0);
    free(value);

    /* non-existent numeric key */
    uint64_t missing_key = 55;
    ASSERT_TRUE(btree_get(tree, (uint8_t *)&missing_key, sizeof(missing_key), &value, &value_size,
                          &vlog_offset, &seq, &ttl, &deleted) != 0);

    /* cursor forward iteration should be in numeric order */
    btree_cursor_t *cursor = NULL;
    ASSERT_TRUE(btree_cursor_init(&cursor, tree) == 0);

    uint64_t prev_key = 0;
    int count = 0;
    while (btree_cursor_valid(cursor))
    {
        uint8_t *k = NULL;
        size_t ks = 0;
        ASSERT_TRUE(btree_cursor_get(cursor, &k, &ks, NULL, NULL, NULL, NULL, NULL, NULL) == 0);
        ASSERT_EQ(ks, sizeof(uint64_t));

        uint64_t kval;
        memcpy(&kval, k, sizeof(uint64_t));
        if (count > 0) ASSERT_TRUE(kval > prev_key);
        prev_key = kval;
        count++;
        btree_cursor_next(cursor);
    }
    ASSERT_EQ(count, 20);

    btree_cursor_free(cursor);
    btree_free(tree);
    btree_builder_free(builder);
    (void)block_manager_close(bm);
    (void)remove(TEST_BTREE_FILE);
}

void test_btree_get_stats(void)
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, TEST_BTREE_FILE, BLOCK_MANAGER_SYNC_NONE) == 0);

    btree_config_t config = {.target_node_size = 4096,
                             .value_threshold = 512,
                             .comparator = NULL,
                             .comparator_ctx = NULL,
                             .cmp_type = BTREE_CMP_MEMCMP};

    btree_builder_t *builder = NULL;
    ASSERT_TRUE(btree_builder_new(&builder, bm, &config) == 0);

    for (int i = 0; i < 200; i++)
    {
        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "key%05d", i);
        snprintf(value, sizeof(value), "value%05d", i);
        ASSERT_TRUE(btree_builder_add(builder, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0, (uint64_t)i, 0, 0) == 0);
    }

    btree_t *tree = NULL;
    ASSERT_TRUE(btree_builder_finish(builder, &tree) == 0);

    btree_stats_t stats;
    ASSERT_EQ(btree_get_stats(tree, &stats), 0);
    ASSERT_EQ(stats.entry_count, 200);
    ASSERT_TRUE(stats.node_count > 1);
    ASSERT_TRUE(stats.height >= 1);
    ASSERT_TRUE(stats.serialized_size > 0);

    /* NULL args */
    ASSERT_EQ(btree_get_stats(NULL, &stats), -1);
    ASSERT_EQ(btree_get_stats(tree, NULL), -1);

    btree_free(tree);
    btree_builder_free(builder);
    (void)block_manager_close(bm);
    (void)remove(TEST_BTREE_FILE);
}

void test_btree_cursor_seek_for_prev(void)
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, TEST_BTREE_FILE, BLOCK_MANAGER_SYNC_NONE) == 0);

    btree_config_t config = {.target_node_size = BTREE_DEFAULT_NODE_SIZE,
                             .value_threshold = 512,
                             .comparator = NULL,
                             .comparator_ctx = NULL,
                             .cmp_type = BTREE_CMP_MEMCMP};

    btree_builder_t *builder = NULL;
    ASSERT_TRUE(btree_builder_new(&builder, bm, &config) == 0);

    /* keys with gaps: key10, key20, key30, key40, key50 */
    for (int i = 1; i <= 5; i++)
    {
        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "key%02d", i * 10);
        snprintf(value, sizeof(value), "value%02d", i * 10);
        ASSERT_TRUE(btree_builder_add(builder, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0, (uint64_t)i, 0, 0) == 0);
    }

    btree_t *tree = NULL;
    ASSERT_TRUE(btree_builder_finish(builder, &tree) == 0);

    btree_cursor_t *cursor = NULL;
    ASSERT_TRUE(btree_cursor_init(&cursor, tree) == 0);

    /* seek_for_prev to exact key */
    ASSERT_EQ(btree_cursor_seek_for_prev(cursor, (uint8_t *)"key30", 6), 0);
    ASSERT_TRUE(btree_cursor_valid(cursor));
    uint8_t *key = NULL;
    size_t key_size = 0;
    ASSERT_EQ(btree_cursor_get(cursor, &key, &key_size, NULL, NULL, NULL, NULL, NULL, NULL), 0);
    ASSERT_EQ(strcmp((char *)key, "key30"), 0);

    /* seek_for_prev to key between existing keys, should position at key <= target */
    ASSERT_EQ(btree_cursor_seek_for_prev(cursor, (uint8_t *)"key35", 6), 0);
    ASSERT_TRUE(btree_cursor_valid(cursor));
    ASSERT_EQ(btree_cursor_get(cursor, &key, &key_size, NULL, NULL, NULL, NULL, NULL, NULL), 0);
    ASSERT_EQ(strcmp((char *)key, "key30"), 0);

    /* seek_for_prev to key after last, should position at last */
    ASSERT_EQ(btree_cursor_seek_for_prev(cursor, (uint8_t *)"key99", 6), 0);
    ASSERT_TRUE(btree_cursor_valid(cursor));
    ASSERT_EQ(btree_cursor_get(cursor, &key, &key_size, NULL, NULL, NULL, NULL, NULL, NULL), 0);
    ASSERT_EQ(strcmp((char *)key, "key50"), 0);

    btree_cursor_free(cursor);
    btree_free(tree);
    btree_builder_free(builder);
    (void)block_manager_close(bm);
    (void)remove(TEST_BTREE_FILE);
}

void test_btree_cursor_has_next_has_prev(void)
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, TEST_BTREE_FILE, BLOCK_MANAGER_SYNC_NONE) == 0);

    btree_config_t config = {.target_node_size = BTREE_DEFAULT_NODE_SIZE,
                             .value_threshold = 512,
                             .comparator = NULL,
                             .comparator_ctx = NULL,
                             .cmp_type = BTREE_CMP_MEMCMP};

    btree_builder_t *builder = NULL;
    ASSERT_TRUE(btree_builder_new(&builder, bm, &config) == 0);

    for (int i = 0; i < 3; i++)
    {
        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "key%05d", i);
        snprintf(value, sizeof(value), "value%05d", i);
        ASSERT_TRUE(btree_builder_add(builder, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0, (uint64_t)i, 0, 0) == 0);
    }

    btree_t *tree = NULL;
    ASSERT_TRUE(btree_builder_finish(builder, &tree) == 0);

    btree_cursor_t *cursor = NULL;
    ASSERT_TRUE(btree_cursor_init(&cursor, tree) == 0);

    /* at first entry: has_prev=0, has_next=1 */
    ASSERT_EQ(btree_cursor_has_prev(cursor), 0);
    ASSERT_EQ(btree_cursor_has_next(cursor), 1);

    /* advance to second */
    ASSERT_EQ(btree_cursor_next(cursor), 0);
    ASSERT_EQ(btree_cursor_has_prev(cursor), 1);
    ASSERT_EQ(btree_cursor_has_next(cursor), 1);

    /* advance to third (last) */
    ASSERT_EQ(btree_cursor_next(cursor), 0);
    ASSERT_EQ(btree_cursor_has_prev(cursor), 1);
    ASSERT_EQ(btree_cursor_has_next(cursor), 0);

    /* advance past end */
    ASSERT_NE(btree_cursor_next(cursor), 0);
    ASSERT_EQ(btree_cursor_has_next(cursor), 0);

    /* NULL args */
    ASSERT_EQ(btree_cursor_has_next(NULL), -1);
    ASSERT_EQ(btree_cursor_has_prev(NULL), -1);

    btree_cursor_free(cursor);
    btree_free(tree);
    btree_builder_free(builder);
    (void)block_manager_close(bm);
    (void)remove(TEST_BTREE_FILE);
}

void test_btree_cursor_goto_first_explicit(void)
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, TEST_BTREE_FILE, BLOCK_MANAGER_SYNC_NONE) == 0);

    btree_config_t config = {.target_node_size = BTREE_DEFAULT_NODE_SIZE,
                             .value_threshold = 512,
                             .comparator = NULL,
                             .comparator_ctx = NULL,
                             .cmp_type = BTREE_CMP_MEMCMP};

    btree_builder_t *builder = NULL;
    ASSERT_TRUE(btree_builder_new(&builder, bm, &config) == 0);

    for (int i = 0; i < 10; i++)
    {
        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "key%05d", i);
        snprintf(value, sizeof(value), "value%05d", i);
        ASSERT_TRUE(btree_builder_add(builder, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0, (uint64_t)i, 0, 0) == 0);
    }

    btree_t *tree = NULL;
    ASSERT_TRUE(btree_builder_finish(builder, &tree) == 0);

    btree_cursor_t *cursor = NULL;
    ASSERT_TRUE(btree_cursor_init(&cursor, tree) == 0);

    /* advance past first few entries */
    btree_cursor_next(cursor);
    btree_cursor_next(cursor);
    btree_cursor_next(cursor);

    uint8_t *key = NULL;
    size_t key_size = 0;
    ASSERT_EQ(btree_cursor_get(cursor, &key, &key_size, NULL, NULL, NULL, NULL, NULL, NULL), 0);
    ASSERT_EQ(strcmp((char *)key, "key00003"), 0);

    /* goto_first should reset to first entry */
    ASSERT_EQ(btree_cursor_goto_first(cursor), 0);
    ASSERT_TRUE(btree_cursor_valid(cursor));

    ASSERT_EQ(btree_cursor_get(cursor, &key, &key_size, NULL, NULL, NULL, NULL, NULL, NULL), 0);
    ASSERT_EQ(strcmp((char *)key, "key00000"), 0);

    /* NULL arg */
    ASSERT_EQ(btree_cursor_goto_first(NULL), -1);

    btree_cursor_free(cursor);
    btree_free(tree);
    btree_builder_free(builder);
    (void)block_manager_close(bm);
    (void)remove(TEST_BTREE_FILE);
}

void test_btree_get_entry_count(void)
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, TEST_BTREE_FILE, BLOCK_MANAGER_SYNC_NONE) == 0);

    btree_config_t config = {.target_node_size = BTREE_DEFAULT_NODE_SIZE,
                             .value_threshold = 512,
                             .comparator = NULL,
                             .comparator_ctx = NULL,
                             .cmp_type = BTREE_CMP_MEMCMP};

    btree_builder_t *builder = NULL;
    ASSERT_TRUE(btree_builder_new(&builder, bm, &config) == 0);

    for (int i = 0; i < 15; i++)
    {
        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "key%05d", i);
        snprintf(value, sizeof(value), "value%05d", i);
        ASSERT_TRUE(btree_builder_add(builder, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0, (uint64_t)i, 0, 0) == 0);
    }

    btree_t *tree = NULL;
    ASSERT_TRUE(btree_builder_finish(builder, &tree) == 0);

    ASSERT_EQ(btree_get_entry_count(tree), 15);
    ASSERT_EQ(btree_get_entry_count(NULL), 0);

    btree_free(tree);
    btree_builder_free(builder);
    (void)block_manager_close(bm);
    (void)remove(TEST_BTREE_FILE);
}

void test_btree_null_args(void)
{
    btree_config_t config = {.target_node_size = BTREE_DEFAULT_NODE_SIZE,
                             .value_threshold = 512,
                             .comparator = NULL,
                             .comparator_ctx = NULL,
                             .cmp_type = BTREE_CMP_MEMCMP};

    /* btree_builder_new NULL args */
    btree_builder_t *builder = NULL;
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, TEST_BTREE_FILE, BLOCK_MANAGER_SYNC_NONE) == 0);

    ASSERT_EQ(btree_builder_new(NULL, bm, &config), -1);
    ASSERT_EQ(btree_builder_new(&builder, NULL, &config), -1);
    ASSERT_EQ(btree_builder_new(&builder, bm, NULL), -1);

    /* btree_builder_add NULL args */
    ASSERT_TRUE(btree_builder_new(&builder, bm, &config) == 0);
    ASSERT_EQ(btree_builder_add(NULL, (uint8_t *)"k", 1, (uint8_t *)"v", 1, 0, 0, 0, 0), -1);
    ASSERT_EQ(btree_builder_add(builder, NULL, 1, (uint8_t *)"v", 1, 0, 0, 0, 0), -1);
    ASSERT_EQ(btree_builder_add(builder, (uint8_t *)"k", 0, (uint8_t *)"v", 1, 0, 0, 0, 0), -1);
    btree_builder_free(builder);

    /* btree_open NULL args */
    btree_t *tree = NULL;
    ASSERT_EQ(btree_open(NULL, bm, &config, 0, 0, 0), -1);
    ASSERT_EQ(btree_open(&tree, NULL, &config, 0, 0, 0), -1);
    ASSERT_EQ(btree_open(&tree, bm, NULL, 0, 0, 0), -1);

    /* btree_get NULL args */
    ASSERT_EQ(btree_get(NULL, (uint8_t *)"k", 1, NULL, NULL, NULL, NULL, NULL, NULL), -1);

    /* btree_get_min_key / btree_get_max_key NULL args */
    uint8_t *key = NULL;
    size_t key_size = 0;
    ASSERT_EQ(btree_get_min_key(NULL, &key, &key_size), -1);
    ASSERT_EQ(btree_get_max_key(NULL, &key, &key_size), -1);

    /* btree_get_max_seq with NULL */
    ASSERT_EQ(btree_get_max_seq(NULL), 0);

    /* cursor NULL args */
    btree_cursor_t *cursor = NULL;
    ASSERT_EQ(btree_cursor_init(NULL, (btree_t *)1), -1);
    ASSERT_EQ(btree_cursor_init(&cursor, NULL), -1);
    ASSERT_EQ(btree_cursor_next(NULL), -1);
    ASSERT_EQ(btree_cursor_prev(NULL), -1);
    ASSERT_EQ(btree_cursor_seek(NULL, (uint8_t *)"k", 1), -1);
    ASSERT_EQ(btree_cursor_seek_for_prev(NULL, (uint8_t *)"k", 1), -1);
    ASSERT_EQ(btree_cursor_goto_first(NULL), -1);
    ASSERT_EQ(btree_cursor_goto_last(NULL), -1);
    ASSERT_EQ(btree_cursor_valid(NULL), -1);
    ASSERT_EQ(btree_cursor_get(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL), -1);

    /* free with NULL should not crash */
    btree_free(NULL);
    btree_builder_free(NULL);
    btree_cursor_free(NULL);
    btree_node_free(NULL);

    (void)block_manager_close(bm);
    (void)remove(TEST_BTREE_FILE);
}

void test_btree_ttl_entries(void)
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, TEST_BTREE_FILE, BLOCK_MANAGER_SYNC_NONE) == 0);

    btree_config_t config = {.target_node_size = BTREE_DEFAULT_NODE_SIZE,
                             .value_threshold = 512,
                             .comparator = NULL,
                             .comparator_ctx = NULL,
                             .cmp_type = BTREE_CMP_MEMCMP};

    btree_builder_t *builder = NULL;
    ASSERT_TRUE(btree_builder_new(&builder, bm, &config) == 0);

    /* add entries with various TTL values */
    ASSERT_TRUE(
        btree_builder_add(builder, (uint8_t *)"key_a", 6, (uint8_t *)"val_a", 6, 0, 1, 0, 0) == 0);
    ASSERT_TRUE(btree_builder_add(builder, (uint8_t *)"key_b", 6, (uint8_t *)"val_b", 6, 0, 2,
                                  1000000, 0) == 0);
    ASSERT_TRUE(btree_builder_add(builder, (uint8_t *)"key_c", 6, (uint8_t *)"val_c", 6, 0, 3,
                                  9999999, 0) == 0);

    btree_t *tree = NULL;
    ASSERT_TRUE(btree_builder_finish(builder, &tree) == 0);
    ASSERT_EQ(tree->entry_count, 3);

    /* verify TTL roundtrips through btree_get */
    uint8_t *value = NULL;
    size_t value_size = 0;
    uint64_t vlog_offset = 0, seq = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;

    ASSERT_EQ(btree_get(tree, (uint8_t *)"key_a", 6, &value, &value_size, &vlog_offset, &seq, &ttl,
                        &deleted),
              0);
    ASSERT_EQ(ttl, 0);
    free(value);

    ASSERT_EQ(btree_get(tree, (uint8_t *)"key_b", 6, &value, &value_size, &vlog_offset, &seq, &ttl,
                        &deleted),
              0);
    ASSERT_EQ(ttl, 1000000);
    free(value);

    ASSERT_EQ(btree_get(tree, (uint8_t *)"key_c", 6, &value, &value_size, &vlog_offset, &seq, &ttl,
                        &deleted),
              0);
    ASSERT_EQ(ttl, 9999999);
    free(value);

    /* verify TTL roundtrips through cursor */
    btree_cursor_t *cursor = NULL;
    ASSERT_TRUE(btree_cursor_init(&cursor, tree) == 0);

    int64_t expected_ttls[] = {0, 1000000, 9999999};
    int idx = 0;
    while (btree_cursor_valid(cursor))
    {
        int64_t cursor_ttl = 0;
        ASSERT_EQ(btree_cursor_get(cursor, NULL, NULL, NULL, NULL, NULL, NULL, &cursor_ttl, NULL),
                  0);
        ASSERT_EQ(cursor_ttl, expected_ttls[idx]);
        idx++;
        btree_cursor_next(cursor);
    }
    ASSERT_EQ(idx, 3);

    btree_cursor_free(cursor);
    btree_free(tree);
    btree_builder_free(builder);
    (void)block_manager_close(bm);
    (void)remove(TEST_BTREE_FILE);
}

void test_btree_vlog_offset_entries(void)
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, TEST_BTREE_FILE, BLOCK_MANAGER_SYNC_NONE) == 0);

    btree_config_t config = {.target_node_size = BTREE_DEFAULT_NODE_SIZE,
                             .value_threshold = 512,
                             .comparator = NULL,
                             .comparator_ctx = NULL,
                             .cmp_type = BTREE_CMP_MEMCMP};

    btree_builder_t *builder = NULL;
    ASSERT_TRUE(btree_builder_new(&builder, bm, &config) == 0);

    /* add entry with inline value (vlog_offset=0) */
    ASSERT_TRUE(btree_builder_add(builder, (uint8_t *)"key_inline", 11, (uint8_t *)"inline_val", 11,
                                  0, 1, 0, 0) == 0);

    /* add entry with vlog reference (vlog_offset != 0, value can be NULL or a stub) */
    ASSERT_TRUE(btree_builder_add(builder, (uint8_t *)"key_vlog_1", 11, NULL, 0, 12345, 2, 0, 0) ==
                0);

    ASSERT_TRUE(btree_builder_add(builder, (uint8_t *)"key_vlog_2", 11, NULL, 0, 99999, 3, 0, 0) ==
                0);

    btree_t *tree = NULL;
    ASSERT_TRUE(btree_builder_finish(builder, &tree) == 0);
    ASSERT_EQ(tree->entry_count, 3);

    /* verify vlog_offset roundtrips through btree_get */
    uint8_t *value = NULL;
    size_t value_size = 0;
    uint64_t vlog_offset = 0, seq = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;

    ASSERT_EQ(btree_get(tree, (uint8_t *)"key_inline", 11, &value, &value_size, &vlog_offset, &seq,
                        &ttl, &deleted),
              0);
    ASSERT_EQ(vlog_offset, 0);
    free(value);

    ASSERT_EQ(btree_get(tree, (uint8_t *)"key_vlog_1", 11, &value, &value_size, &vlog_offset, &seq,
                        &ttl, &deleted),
              0);
    ASSERT_EQ(vlog_offset, 12345);
    if (value) free(value);

    ASSERT_EQ(btree_get(tree, (uint8_t *)"key_vlog_2", 11, &value, &value_size, &vlog_offset, &seq,
                        &ttl, &deleted),
              0);
    ASSERT_EQ(vlog_offset, 99999);
    if (value) free(value);

    /* verify vlog_offset roundtrips through cursor */
    btree_cursor_t *cursor = NULL;
    ASSERT_TRUE(btree_cursor_init(&cursor, tree) == 0);

    uint64_t expected_offsets[] = {0, 12345, 99999};
    int idx = 0;
    while (btree_cursor_valid(cursor))
    {
        uint64_t cursor_vlog = 0;
        ASSERT_EQ(btree_cursor_get(cursor, NULL, NULL, NULL, NULL, &cursor_vlog, NULL, NULL, NULL),
                  0);
        ASSERT_EQ(cursor_vlog, expected_offsets[idx]);
        idx++;
        btree_cursor_next(cursor);
    }
    ASSERT_EQ(idx, 3);

    btree_cursor_free(cursor);
    btree_free(tree);
    btree_builder_free(builder);
    (void)block_manager_close(bm);
    (void)remove(TEST_BTREE_FILE);
}

void bench_btree_build()
{
    int sizes[] = {1000, 10000, 100000};
    int num_sizes = sizeof(sizes) / sizeof(sizes[0]);

    for (int s = 0; s < num_sizes; s++)
    {
        int num_entries = sizes[s];
        block_manager_t *bm = NULL;
        ASSERT_TRUE(block_manager_open(&bm, TEST_BTREE_FILE, BLOCK_MANAGER_SYNC_NONE) == 0);

        btree_config_t config = {.target_node_size = 4096,
                                 .value_threshold = 512,
                                 .comparator = NULL,
                                 .comparator_ctx = NULL,
                                 .cmp_type = BTREE_CMP_MEMCMP};

        btree_builder_t *builder = NULL;
        ASSERT_TRUE(btree_builder_new(&builder, bm, &config) == 0);

        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);

        for (int i = 0; i < num_entries; i++)
        {
            char key[32];
            char value[128];
            snprintf(key, sizeof(key), "key%08d", i);
            snprintf(value, sizeof(value), "value%08d_data", i);
            btree_builder_add(builder, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                              strlen(value) + 1, 0, (uint64_t)i, 0, 0);
        }

        btree_t *tree = NULL;
        btree_builder_finish(builder, &tree);

        clock_gettime(CLOCK_MONOTONIC, &end);

        double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1000000000.0;
        double ops_per_sec = num_entries / elapsed;

        printf("  Build %d entries: %.3f sec (%.0f ops/sec), %" PRIu64 " nodes\n", num_entries,
               elapsed, ops_per_sec, tree->node_count);

        btree_free(tree);
        btree_builder_free(builder);
        (void)block_manager_close(bm);
        (void)remove(TEST_BTREE_FILE);
    }
}

void bench_btree_get()
{
    int num_entries = 100000;
    int num_lookups = 10000;

    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, TEST_BTREE_FILE, BLOCK_MANAGER_SYNC_NONE) == 0);

    btree_config_t config = {.target_node_size = 4096,
                             .value_threshold = 512,
                             .comparator = NULL,
                             .comparator_ctx = NULL,
                             .cmp_type = BTREE_CMP_MEMCMP};

    btree_builder_t *builder = NULL;
    ASSERT_TRUE(btree_builder_new(&builder, bm, &config) == 0);

    for (int i = 0; i < num_entries; i++)
    {
        char key[32];
        char value[128];
        snprintf(key, sizeof(key), "key%08d", i);
        snprintf(value, sizeof(value), "value%08d_data", i);
        btree_builder_add(builder, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                          strlen(value) + 1, 0, (uint64_t)i, 0, 0);
    }

    btree_t *tree = NULL;
    btree_builder_finish(builder, &tree);

    struct timespec start, end;
    double elapsed;

    printf("  [No Cache]\n");

    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < num_lookups; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key%08d", i % num_entries);

        uint8_t *value = NULL;
        size_t value_size = 0;
        uint64_t vlog_offset = 0;
        uint64_t seq = 0;
        int64_t ttl = 0;
        uint8_t deleted = 0;

        btree_get(tree, (uint8_t *)key, strlen(key) + 1, &value, &value_size, &vlog_offset, &seq,
                  &ttl, &deleted);
        free(value);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1000000000.0;
    printf("    Sequential %d lookups: %.3f sec (%.0f ops/sec)\n", num_lookups, elapsed,
           num_lookups / elapsed);

    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < num_lookups; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key%08d", rand() % num_entries);

        uint8_t *value = NULL;
        size_t value_size = 0;
        uint64_t vlog_offset = 0;
        uint64_t seq = 0;
        int64_t ttl = 0;
        uint8_t deleted = 0;

        btree_get(tree, (uint8_t *)key, strlen(key) + 1, &value, &value_size, &vlog_offset, &seq,
                  &ttl, &deleted);
        free(value);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1000000000.0;
    printf("    Random %d lookups: %.3f sec (%.0f ops/sec)\n", num_lookups, elapsed,
           num_lookups / elapsed);

    printf("  [With Node Cache]\n");

    clock_cache_t *node_cache = btree_create_node_cache(1024 * 1024);
    btree_set_node_cache(tree, node_cache);

    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < num_lookups; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key%08d", i % num_entries);

        uint8_t *value = NULL;
        size_t value_size = 0;
        uint64_t vlog_offset = 0;
        uint64_t seq = 0;
        int64_t ttl = 0;
        uint8_t deleted = 0;

        btree_get(tree, (uint8_t *)key, strlen(key) + 1, &value, &value_size, &vlog_offset, &seq,
                  &ttl, &deleted);
        free(value);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1000000000.0;
    printf("    Sequential %d lookups: %.3f sec (%.0f ops/sec)\n", num_lookups, elapsed,
           num_lookups / elapsed);

    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < num_lookups; i++)
    {
        char key[32];
        snprintf(key, sizeof(key), "key%08d", rand() % num_entries);

        uint8_t *value = NULL;
        size_t value_size = 0;
        uint64_t vlog_offset = 0;
        uint64_t seq = 0;
        int64_t ttl = 0;
        uint8_t deleted = 0;

        btree_get(tree, (uint8_t *)key, strlen(key) + 1, &value, &value_size, &vlog_offset, &seq,
                  &ttl, &deleted);
        free(value);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1000000000.0;
    printf("    Random %d lookups: %.3f sec (%.0f ops/sec)\n", num_lookups, elapsed,
           num_lookups / elapsed);

    clock_cache_stats_t stats;
    clock_cache_get_stats(node_cache, &stats);
    printf("    Cache stats: %zu entries, %.1f%% hit rate\n", stats.total_entries,
           stats.hit_rate * 100.0);

    btree_set_node_cache(tree, NULL);
    clock_cache_destroy(node_cache);
    btree_free(tree);
    btree_builder_free(builder);
    (void)block_manager_close(bm);
    (void)remove(TEST_BTREE_FILE);
}

void test_btree_compression_lz4()
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, TEST_BTREE_FILE, BLOCK_MANAGER_SYNC_NONE) == 0);

    btree_config_t config = {.target_node_size = BTREE_DEFAULT_NODE_SIZE,
                             .value_threshold = 512,
                             .comparator = NULL,
                             .comparator_ctx = NULL,
                             .cmp_type = BTREE_CMP_MEMCMP,
                             .compression_algo = TDB_COMPRESS_LZ4};

    btree_builder_t *builder = NULL;
    ASSERT_TRUE(btree_builder_new(&builder, bm, &config) == 0);

    for (int i = 0; i < 100; i++)
    {
        char key[32];
        char value[128];
        snprintf(key, sizeof(key), "key%08d", i);
        snprintf(value, sizeof(value), "value%08d_data_padding_for_compression", i);
        ASSERT_TRUE(btree_builder_add(builder, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0, (uint64_t)i, 0, 0) == 0);
    }

    btree_t *tree = NULL;
    ASSERT_TRUE(btree_builder_finish(builder, &tree) == 0);
    ASSERT_TRUE(tree != NULL);
    ASSERT_EQ(tree->entry_count, 100);
    uint8_t *value = NULL;
    size_t value_size = 0;
    uint64_t vlog_offset = 0, seq = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;

    ASSERT_TRUE(btree_get(tree, (uint8_t *)"key00000000", 12, &value, &value_size, &vlog_offset,
                          &seq, &ttl, &deleted) == 0);
    ASSERT_TRUE(value != NULL);
    free(value);

    ASSERT_TRUE(btree_get(tree, (uint8_t *)"key00000050", 12, &value, &value_size, &vlog_offset,
                          &seq, &ttl, &deleted) == 0);
    ASSERT_TRUE(value != NULL);
    free(value);

    ASSERT_TRUE(btree_get(tree, (uint8_t *)"key00000099", 12, &value, &value_size, &vlog_offset,
                          &seq, &ttl, &deleted) == 0);
    ASSERT_TRUE(value != NULL);
    free(value);

    btree_free(tree);
    btree_builder_free(builder);
    (void)block_manager_close(bm);
    (void)remove(TEST_BTREE_FILE);
}

void test_btree_compression_zstd()
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, TEST_BTREE_FILE, BLOCK_MANAGER_SYNC_NONE) == 0);

    btree_config_t config = {.target_node_size = BTREE_DEFAULT_NODE_SIZE,
                             .value_threshold = 512,
                             .comparator = NULL,
                             .comparator_ctx = NULL,
                             .cmp_type = BTREE_CMP_MEMCMP,
                             .compression_algo = TDB_COMPRESS_ZSTD};

    btree_builder_t *builder = NULL;
    ASSERT_TRUE(btree_builder_new(&builder, bm, &config) == 0);

    for (int i = 0; i < 100; i++)
    {
        char key[32];
        char value[128];
        snprintf(key, sizeof(key), "key%08d", i);
        snprintf(value, sizeof(value), "value%08d_data_padding_for_compression", i);
        ASSERT_TRUE(btree_builder_add(builder, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0, (uint64_t)i, 0, 0) == 0);
    }

    btree_t *tree = NULL;
    ASSERT_TRUE(btree_builder_finish(builder, &tree) == 0);
    ASSERT_TRUE(tree != NULL);
    ASSERT_EQ(tree->entry_count, 100);

    btree_cursor_t *cursor = NULL;
    ASSERT_TRUE(btree_cursor_init(&cursor, tree) == 0);

    int count = 0;
    while (btree_cursor_valid(cursor))
    {
        count++;
        btree_cursor_next(cursor);
    }
    ASSERT_EQ(count, 100);

    btree_cursor_free(cursor);
    btree_free(tree);
    btree_builder_free(builder);
    (void)block_manager_close(bm);
    (void)remove(TEST_BTREE_FILE);
}

void test_btree_compression_two_leaves()
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, TEST_BTREE_FILE, BLOCK_MANAGER_SYNC_NONE) == 0);

    btree_config_t config = {.target_node_size = 512,
                             .value_threshold = 256,
                             .comparator = NULL,
                             .comparator_ctx = NULL,
                             .cmp_type = BTREE_CMP_MEMCMP,
                             .compression_algo = TDB_COMPRESS_LZ4};

    btree_builder_t *builder = NULL;
    ASSERT_TRUE(btree_builder_new(&builder, bm, &config) == 0);

    for (int i = 0; i < 20; i++)
    {
        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "key%08d", i);
        snprintf(value, sizeof(value), "value%08d_padding", i);
        ASSERT_TRUE(btree_builder_add(builder, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0, (uint64_t)i, 0, 0) == 0);
    }

    btree_t *tree = NULL;
    int result = btree_builder_finish(builder, &tree);
    ASSERT_TRUE(result == 0);
    ASSERT_TRUE(tree != NULL);
    ASSERT_EQ(tree->entry_count, 20);

    uint8_t *value = NULL;
    size_t value_size = 0;
    uint64_t vlog_offset = 0, seq = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;

    ASSERT_TRUE(btree_get(tree, (uint8_t *)"key00000000", 12, &value, &value_size, &vlog_offset,
                          &seq, &ttl, &deleted) == 0);
    free(value);

    btree_free(tree);
    btree_builder_free(builder);
    (void)block_manager_close(bm);
    (void)remove(TEST_BTREE_FILE);
}

void test_btree_compression_three_leaves()
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, TEST_BTREE_FILE, BLOCK_MANAGER_SYNC_NONE) == 0);

    btree_config_t config = {.target_node_size = 512,
                             .value_threshold = 256,
                             .comparator = NULL,
                             .comparator_ctx = NULL,
                             .cmp_type = BTREE_CMP_MEMCMP,
                             .compression_algo = TDB_COMPRESS_LZ4};

    btree_builder_t *builder = NULL;
    ASSERT_TRUE(btree_builder_new(&builder, bm, &config) == 0);

    for (int i = 0; i < 40; i++)
    {
        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "key%08d", i);
        snprintf(value, sizeof(value), "value%08d_padding", i);
        ASSERT_TRUE(btree_builder_add(builder, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0, (uint64_t)i, 0, 0) == 0);
    }

    btree_t *tree = NULL;
    ASSERT_TRUE(btree_builder_finish(builder, &tree) == 0);
    ASSERT_TRUE(tree != NULL);

    btree_free(tree);
    btree_builder_free(builder);
    (void)block_manager_close(bm);
    (void)remove(TEST_BTREE_FILE);
}

void test_btree_compression_cursor_bidirectional()
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, TEST_BTREE_FILE, BLOCK_MANAGER_SYNC_NONE) == 0);

    btree_config_t config = {.target_node_size = 4096,
                             .value_threshold = 512,
                             .comparator = NULL,
                             .comparator_ctx = NULL,
                             .cmp_type = BTREE_CMP_MEMCMP,
                             .compression_algo = TDB_COMPRESS_LZ4};

    btree_builder_t *builder = NULL;
    ASSERT_TRUE(btree_builder_new(&builder, bm, &config) == 0);

    for (int i = 0; i < 500; i++)
    {
        char key[32];
        char value[128];
        snprintf(key, sizeof(key), "key%08d", i);
        snprintf(value, sizeof(value), "value%08d_data_padding_for_compression_test", i);
        ASSERT_TRUE(btree_builder_add(builder, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0, (uint64_t)i, 0, 0) == 0);
    }

    btree_t *tree = NULL;
    ASSERT_TRUE(btree_builder_finish(builder, &tree) == 0);
    ASSERT_TRUE(tree != NULL);
    ASSERT_EQ(tree->entry_count, 500);

    btree_cursor_t *cursor = NULL;
    ASSERT_TRUE(btree_cursor_init(&cursor, tree) == 0);

    int forward_count = 0;
    while (btree_cursor_valid(cursor))
    {
        forward_count++;
        btree_cursor_next(cursor);
    }
    ASSERT_EQ(forward_count, 500);

    btree_cursor_free(cursor);

    ASSERT_TRUE(btree_cursor_init(&cursor, tree) == 0);
    ASSERT_TRUE(btree_cursor_goto_last(cursor) == 0);

    int backward_count = 0;
    while (btree_cursor_valid(cursor))
    {
        backward_count++;
        btree_cursor_prev(cursor);
    }
    ASSERT_EQ(backward_count, 500);

    btree_cursor_free(cursor);
    btree_free(tree);
    btree_builder_free(builder);
    (void)block_manager_close(bm);
    (void)remove(TEST_BTREE_FILE);
}

void test_btree_compression_single_leaf()
{
    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, TEST_BTREE_FILE, BLOCK_MANAGER_SYNC_NONE) == 0);

    btree_config_t config = {.target_node_size = BTREE_DEFAULT_NODE_SIZE,
                             .value_threshold = 512,
                             .comparator = NULL,
                             .comparator_ctx = NULL,
                             .cmp_type = BTREE_CMP_MEMCMP,
                             .compression_algo = TDB_COMPRESS_LZ4};

    btree_builder_t *builder = NULL;
    ASSERT_TRUE(btree_builder_new(&builder, bm, &config) == 0);

    /* we add just 5 entries */
    for (int i = 0; i < 5; i++)
    {
        char key[32];
        char value[64];
        snprintf(key, sizeof(key), "key%d", i);
        snprintf(value, sizeof(value), "value%d", i);
        ASSERT_TRUE(btree_builder_add(builder, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                                      strlen(value) + 1, 0, (uint64_t)i, 0, 0) == 0);
    }

    btree_t *tree = NULL;
    ASSERT_TRUE(btree_builder_finish(builder, &tree) == 0);
    ASSERT_TRUE(tree != NULL);
    ASSERT_EQ(tree->entry_count, 5);

    /* we verify reads */
    uint8_t *value = NULL;
    size_t value_size = 0;
    uint64_t vlog_offset = 0, seq = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;

    ASSERT_TRUE(btree_get(tree, (uint8_t *)"key0", 5, &value, &value_size, &vlog_offset, &seq, &ttl,
                          &deleted) == 0);
    ASSERT_TRUE(value != NULL);
    free(value);

    btree_free(tree);
    btree_builder_free(builder);
    (void)block_manager_close(bm);
    (void)remove(TEST_BTREE_FILE);
}

void bench_btree_cursor_scan()
{
    int num_entries = 100000;

    block_manager_t *bm = NULL;
    ASSERT_TRUE(block_manager_open(&bm, TEST_BTREE_FILE, BLOCK_MANAGER_SYNC_NONE) == 0);

    btree_config_t config = {.target_node_size = 4096,
                             .value_threshold = 512,
                             .comparator = NULL,
                             .comparator_ctx = NULL,
                             .cmp_type = BTREE_CMP_MEMCMP};

    btree_builder_t *builder = NULL;
    ASSERT_TRUE(btree_builder_new(&builder, bm, &config) == 0);

    for (int i = 0; i < num_entries; i++)
    {
        char key[32];
        char value[128];
        snprintf(key, sizeof(key), "key%08d", i);
        snprintf(value, sizeof(value), "value%08d_data", i);
        btree_builder_add(builder, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                          strlen(value) + 1, 0, (uint64_t)i, 0, 0);
    }

    btree_t *tree = NULL;
    btree_builder_finish(builder, &tree);

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    btree_cursor_t *cursor = NULL;
    btree_cursor_init(&cursor, tree);

    int count = 0;
    while (btree_cursor_valid(cursor))
    {
        count++;
        btree_cursor_next(cursor);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1000000000.0;
    printf("  Forward scan %d entries: %.3f sec (%.0f entries/sec)\n", count, elapsed,
           count / elapsed);

    btree_cursor_free(cursor);

    clock_gettime(CLOCK_MONOTONIC, &start);

    btree_cursor_init(&cursor, tree);
    btree_cursor_goto_last(cursor);

    count = 0;
    while (btree_cursor_valid(cursor))
    {
        count++;
        btree_cursor_prev(cursor);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1000000000.0;
    printf("  Backward scan %d entries: %.3f sec (%.0f entries/sec)\n", count, elapsed,
           count / elapsed);

    btree_cursor_free(cursor);
    btree_free(tree);
    btree_builder_free(builder);
    (void)block_manager_close(bm);
    (void)remove(TEST_BTREE_FILE);
}

void bench_btree_compression_comparison()
{
    const int num_entries = 100000;
    const char *no_compress_file = "test_btree_nocompress.db";
    const char *lz4_file = "test_btree_lz4.db";
    const char *zstd_file = "test_btree_zstd.db";

    struct timespec start, end;
    double build_time_none, build_time_lz4, build_time_zstd;
    double get_time_none, get_time_lz4, get_time_zstd;
    uint64_t file_size_none, file_size_lz4, file_size_zstd;

    {
        block_manager_t *bm = NULL;
        block_manager_open(&bm, no_compress_file, BLOCK_MANAGER_SYNC_NONE);

        btree_config_t config = {.target_node_size = 4096,
                                 .value_threshold = 512,
                                 .comparator = NULL,
                                 .comparator_ctx = NULL,
                                 .cmp_type = BTREE_CMP_MEMCMP,
                                 .compression_algo = TDB_COMPRESS_NONE};

        btree_builder_t *builder = NULL;
        btree_builder_new(&builder, bm, &config);

        clock_gettime(CLOCK_MONOTONIC, &start);
        for (int i = 0; i < num_entries; i++)
        {
            char key[32];
            char value[128];
            snprintf(key, sizeof(key), "key%08d", i);
            snprintf(value, sizeof(value), "value%08d_data_padding_for_realistic_size_test", i);
            btree_builder_add(builder, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                              strlen(value) + 1, 0, (uint64_t)i, 0, 0);
        }

        btree_t *tree = NULL;
        btree_builder_finish(builder, &tree);
        clock_gettime(CLOCK_MONOTONIC, &end);
        build_time_none = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

        clock_cache_t *cache_none = btree_create_node_cache(10 * 1024 * 1024); /* 10MB cache */
        btree_set_node_cache(tree, cache_none);

        clock_gettime(CLOCK_MONOTONIC, &start);
        for (int i = 0; i < 10000; i++)
        {
            char key[32];
            snprintf(key, sizeof(key), "key%08d", (i * 7) % num_entries);
            uint8_t *value = NULL;
            size_t value_size = 0;
            uint64_t vlog_offset = 0, seq = 0;
            int64_t ttl = 0;
            uint8_t deleted = 0;
            btree_get(tree, (uint8_t *)key, strlen(key) + 1, &value, &value_size, &vlog_offset,
                      &seq, &ttl, &deleted);
            free(value);
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        get_time_none = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

        block_manager_get_size(bm, &file_size_none);

        btree_free(tree);
        btree_builder_free(builder);
        clock_cache_destroy(cache_none);
        block_manager_close(bm);
    }

    {
        block_manager_t *bm = NULL;
        block_manager_open(&bm, lz4_file, BLOCK_MANAGER_SYNC_NONE);

        btree_config_t config = {.target_node_size = 4096,
                                 .value_threshold = 512,
                                 .comparator = NULL,
                                 .comparator_ctx = NULL,
                                 .cmp_type = BTREE_CMP_MEMCMP,
                                 .compression_algo = TDB_COMPRESS_LZ4};

        btree_builder_t *builder = NULL;
        btree_builder_new(&builder, bm, &config);

        clock_gettime(CLOCK_MONOTONIC, &start);
        for (int i = 0; i < num_entries; i++)
        {
            char key[32];
            char value[128];
            snprintf(key, sizeof(key), "key%08d", i);
            snprintf(value, sizeof(value), "value%08d_data_padding_for_realistic_size_test", i);
            btree_builder_add(builder, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                              strlen(value) + 1, 0, (uint64_t)i, 0, 0);
        }

        btree_t *tree = NULL;
        btree_builder_finish(builder, &tree);
        clock_gettime(CLOCK_MONOTONIC, &end);
        build_time_lz4 = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

        clock_cache_t *cache_lz4 = btree_create_node_cache(10 * 1024 * 1024); /* 10MB cache */
        btree_set_node_cache(tree, cache_lz4);

        clock_gettime(CLOCK_MONOTONIC, &start);
        for (int i = 0; i < 10000; i++)
        {
            char key[32];
            snprintf(key, sizeof(key), "key%08d", (i * 7) % num_entries);
            uint8_t *value = NULL;
            size_t value_size = 0;
            uint64_t vlog_offset = 0, seq = 0;
            int64_t ttl = 0;
            uint8_t deleted = 0;
            btree_get(tree, (uint8_t *)key, strlen(key) + 1, &value, &value_size, &vlog_offset,
                      &seq, &ttl, &deleted);
            free(value);
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        get_time_lz4 = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

        block_manager_get_size(bm, &file_size_lz4);

        btree_free(tree);
        btree_builder_free(builder);
        clock_cache_destroy(cache_lz4);
        block_manager_close(bm);
    }

    {
        block_manager_t *bm = NULL;
        block_manager_open(&bm, zstd_file, BLOCK_MANAGER_SYNC_NONE);

        btree_config_t config = {.target_node_size = 4096,
                                 .value_threshold = 512,
                                 .comparator = NULL,
                                 .comparator_ctx = NULL,
                                 .cmp_type = BTREE_CMP_MEMCMP,
                                 .compression_algo = TDB_COMPRESS_ZSTD};

        btree_builder_t *builder = NULL;
        btree_builder_new(&builder, bm, &config);

        clock_gettime(CLOCK_MONOTONIC, &start);
        for (int i = 0; i < num_entries; i++)
        {
            char key[32];
            char value[128];
            snprintf(key, sizeof(key), "key%08d", i);
            snprintf(value, sizeof(value), "value%08d_data_padding_for_realistic_size_test", i);
            btree_builder_add(builder, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                              strlen(value) + 1, 0, (uint64_t)i, 0, 0);
        }

        btree_t *tree = NULL;
        btree_builder_finish(builder, &tree);
        clock_gettime(CLOCK_MONOTONIC, &end);
        build_time_zstd = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

        clock_cache_t *cache_zstd = btree_create_node_cache(10 * 1024 * 1024); /* 10MB cache */
        btree_set_node_cache(tree, cache_zstd);

        clock_gettime(CLOCK_MONOTONIC, &start);
        for (int i = 0; i < 10000; i++)
        {
            char key[32];
            snprintf(key, sizeof(key), "key%08d", (i * 7) % num_entries);
            uint8_t *value = NULL;
            size_t value_size = 0;
            uint64_t vlog_offset = 0, seq = 0;
            int64_t ttl = 0;
            uint8_t deleted = 0;
            btree_get(tree, (uint8_t *)key, strlen(key) + 1, &value, &value_size, &vlog_offset,
                      &seq, &ttl, &deleted);
            free(value);
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        get_time_zstd = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

        block_manager_get_size(bm, &file_size_zstd);

        btree_free(tree);
        btree_builder_free(builder);
        clock_cache_destroy(cache_zstd);
        block_manager_close(bm);
    }

    printf("\n  %-12s %12s %12s %12s\n", "Metric", "No Compress", "LZ4", "ZSTD");
    printf("  %-12s %12s %12s %12s\n", "------", "-----------", "---", "----");
    printf("  %-12s %10.3f s %10.3f s %10.3f s\n", "Build Time", build_time_none, build_time_lz4,
           build_time_zstd);
    printf("  %-12s %10.3f s %10.3f s %10.3f s\n", "10K Gets", get_time_none, get_time_lz4,
           get_time_zstd);
    printf("  %-12s %9.2f MB %9.2f MB %9.2f MB\n", "File Size", file_size_none / (1024.0 * 1024.0),
           file_size_lz4 / (1024.0 * 1024.0), file_size_zstd / (1024.0 * 1024.0));
    printf("  %-12s %11s %10.1f%% %10.1f%%\n", "Compression", "baseline",
           (1.0 - (double)file_size_lz4 / file_size_none) * 100,
           (1.0 - (double)file_size_zstd / file_size_none) * 100);
    printf("  %-12s %11s %10.2fx %10.2fx\n", "Get Speedup", "baseline",
           get_time_none / get_time_lz4, get_time_none / get_time_zstd);

    remove(no_compress_file);
    remove(lz4_file);
    remove(zstd_file);
}

void bench_btree_node_sizes()
{
    const int num_entries = 100000;
    const size_t node_sizes[] = {4096, 8192, 16384, 32768, 65536};
    const int num_sizes = sizeof(node_sizes) / sizeof(node_sizes[0]);

    printf("\n  Node Size Benchmark (%d entries)\n", num_entries);
    printf("  %-12s %12s %12s %12s %12s\n", "Node Size", "Build Time", "10K Gets", "File Size",
           "Nodes");
    printf("  %-12s %12s %12s %12s %12s\n", "---------", "----------", "--------", "---------",
           "-----");

    for (int s = 0; s < num_sizes; s++)
    {
        char test_file[64];
        snprintf(test_file, sizeof(test_file), "test_btree_nodesize_%zu.db", node_sizes[s]);

        block_manager_t *bm = NULL;
        block_manager_open(&bm, test_file, BLOCK_MANAGER_SYNC_NONE);

        btree_config_t config = {.target_node_size = node_sizes[s],
                                 .value_threshold = 512,
                                 .comparator = NULL,
                                 .comparator_ctx = NULL,
                                 .cmp_type = BTREE_CMP_MEMCMP,
                                 .compression_algo = TDB_COMPRESS_NONE};

        btree_builder_t *builder = NULL;
        btree_builder_new(&builder, bm, &config);

        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        for (int i = 0; i < num_entries; i++)
        {
            char key[32];
            char value[128];
            snprintf(key, sizeof(key), "key%08d", i);
            snprintf(value, sizeof(value), "value%08d_data_padding_for_realistic_size_test", i);
            btree_builder_add(builder, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                              strlen(value) + 1, 0, (uint64_t)i, 0, 0);
        }

        btree_t *tree = NULL;
        btree_builder_finish(builder, &tree);
        clock_gettime(CLOCK_MONOTONIC, &end);
        double build_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

        clock_cache_t *cache = btree_create_node_cache(10 * 1024 * 1024);
        btree_set_node_cache(tree, cache);

        clock_gettime(CLOCK_MONOTONIC, &start);
        for (int i = 0; i < 10000; i++)
        {
            char key[32];
            snprintf(key, sizeof(key), "key%08d", (i * 7) % num_entries);
            uint8_t *value = NULL;
            size_t value_size = 0;
            uint64_t vlog_offset = 0, seq = 0;
            int64_t ttl = 0;
            uint8_t deleted = 0;
            btree_get(tree, (uint8_t *)key, strlen(key) + 1, &value, &value_size, &vlog_offset,
                      &seq, &ttl, &deleted);
            free(value);
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        double get_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

        uint64_t file_size;
        block_manager_get_size(bm, &file_size);

        printf("  %10zuB %10.3f s %10.3f s %9.2f MB %12" PRIu64 "\n", node_sizes[s], build_time,
               get_time, file_size / (1024.0 * 1024.0), tree->node_count);

        btree_free(tree);
        btree_builder_free(builder);
        clock_cache_destroy(cache);
        block_manager_close(bm);
        remove(test_file);
    }

    /* now test with compression enabled */
    printf("\n  Node Size Benchmark with LZ4 Compression (%d entries)\n", num_entries);
    printf("  %-12s %12s %12s %12s %12s\n", "Node Size", "Build Time", "10K Gets", "File Size",
           "Nodes");
    printf("  %-12s %12s %12s %12s %12s\n", "---------", "----------", "--------", "---------",
           "-----");

    for (int s = 0; s < num_sizes; s++)
    {
        char test_file[64];
        snprintf(test_file, sizeof(test_file), "test_btree_nodesize_lz4_%zu.db", node_sizes[s]);

        block_manager_t *bm = NULL;
        block_manager_open(&bm, test_file, BLOCK_MANAGER_SYNC_NONE);

        btree_config_t config = {.target_node_size = node_sizes[s],
                                 .value_threshold = 512,
                                 .comparator = NULL,
                                 .comparator_ctx = NULL,
                                 .cmp_type = BTREE_CMP_MEMCMP,
                                 .compression_algo = TDB_COMPRESS_LZ4};

        btree_builder_t *builder = NULL;
        btree_builder_new(&builder, bm, &config);

        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        for (int i = 0; i < num_entries; i++)
        {
            char key[32];
            char value[128];
            snprintf(key, sizeof(key), "key%08d", i);
            snprintf(value, sizeof(value), "value%08d_data_padding_for_realistic_size_test", i);
            btree_builder_add(builder, (uint8_t *)key, strlen(key) + 1, (uint8_t *)value,
                              strlen(value) + 1, 0, (uint64_t)i, 0, 0);
        }

        btree_t *tree = NULL;
        btree_builder_finish(builder, &tree);
        clock_gettime(CLOCK_MONOTONIC, &end);
        double build_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

        clock_cache_t *cache = btree_create_node_cache(10 * 1024 * 1024);
        btree_set_node_cache(tree, cache);

        clock_gettime(CLOCK_MONOTONIC, &start);
        for (int i = 0; i < 10000; i++)
        {
            char key[32];
            snprintf(key, sizeof(key), "key%08d", (i * 7) % num_entries);
            uint8_t *value = NULL;
            size_t value_size = 0;
            uint64_t vlog_offset = 0, seq = 0;
            int64_t ttl = 0;
            uint8_t deleted = 0;
            btree_get(tree, (uint8_t *)key, strlen(key) + 1, &value, &value_size, &vlog_offset,
                      &seq, &ttl, &deleted);
            free(value);
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        double get_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

        uint64_t file_size;
        block_manager_get_size(bm, &file_size);

        printf("  %10zuB %10.3f s %10.3f s %9.2f MB %12" PRIu64 "\n", node_sizes[s], build_time,
               get_time, file_size / (1024.0 * 1024.0), tree->node_count);

        btree_free(tree);
        btree_builder_free(builder);
        clock_cache_destroy(cache);
        block_manager_close(bm);
        remove(test_file);
    }
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_btree_builder_new, tests_passed);
    RUN_TEST(test_btree_builder_add_single, tests_passed);
    RUN_TEST(test_btree_builder_add_multiple, tests_passed);
    RUN_TEST(test_btree_get, tests_passed);
    RUN_TEST(test_btree_cursor_forward, tests_passed);
    RUN_TEST(test_btree_cursor_backward, tests_passed);
    RUN_TEST(test_btree_cursor_seek, tests_passed);
    RUN_TEST(test_btree_min_max_keys, tests_passed);
    RUN_TEST(test_btree_max_seq, tests_passed);
    RUN_TEST(test_btree_open_existing, tests_passed);
    RUN_TEST(test_btree_tombstone, tests_passed);
    RUN_TEST(test_btree_large_dataset, tests_passed);
    RUN_TEST(test_btree_empty_tree, tests_passed);
    RUN_TEST(test_btree_single_entry, tests_passed);
    RUN_TEST(test_btree_duplicate_keys, tests_passed);
    RUN_TEST(test_btree_large_keys_values, tests_passed);
    RUN_TEST(test_btree_seek_edge_cases, tests_passed);
    RUN_TEST(test_btree_compression_single_leaf, tests_passed);
    RUN_TEST(test_btree_compression_lz4, tests_passed);
    RUN_TEST(test_btree_compression_zstd, tests_passed);
    RUN_TEST(test_btree_compression_two_leaves, tests_passed);
    RUN_TEST(test_btree_compression_three_leaves, tests_passed);
    RUN_TEST(test_btree_compression_cursor_bidirectional, tests_passed);
    RUN_TEST(test_btree_arena, tests_passed);
    RUN_TEST(test_btree_comparator_string, tests_passed);
    RUN_TEST(test_btree_comparator_numeric, tests_passed);
    RUN_TEST(test_btree_get_stats, tests_passed);
    RUN_TEST(test_btree_cursor_seek_for_prev, tests_passed);
    RUN_TEST(test_btree_cursor_has_next_has_prev, tests_passed);
    RUN_TEST(test_btree_cursor_goto_first_explicit, tests_passed);
    RUN_TEST(test_btree_get_entry_count, tests_passed);
    RUN_TEST(test_btree_null_args, tests_passed);
    RUN_TEST(test_btree_ttl_entries, tests_passed);
    RUN_TEST(test_btree_vlog_offset_entries, tests_passed);

    RUN_TEST(bench_btree_build, tests_passed);
    RUN_TEST(bench_btree_get, tests_passed);
    RUN_TEST(bench_btree_cursor_scan, tests_passed);
    RUN_TEST(bench_btree_compression_comparison, tests_passed);
    RUN_TEST(bench_btree_node_sizes, tests_passed);

    PRINT_TEST_RESULTS(tests_passed, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
