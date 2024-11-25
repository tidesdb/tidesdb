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
#include <unistd.h>

#include "../src/skiplist.h"
#include "test_macros.h"

#define CONCURRENT_NUM_THREADS    10
#define CONCURRENT_NUM_OPERATIONS 1000

void test_skiplist_create_node()
{
    unsigned char key[] = "key";
    unsigned char value[] = "value";
    skiplist_node *node = skiplist_create_node(3, key, sizeof(key), value, sizeof(value), -1);
    assert(node != NULL);
    assert(memcmp(node->key, key, sizeof(key)) == 0);
    assert(memcmp(node->value, value, sizeof(value)) == 0);
    assert(node->ttl == -1);
    skiplist_destroy_node(node);

    printf(GREEN "test_skiplist_create_node passed\n" RESET);
}

void test_new_skiplist()
{
    skiplist *list = new_skiplist(12, 0.24f);
    assert(list != NULL);
    assert(list->level == 1);
    assert(list->max_level == 12);
    assert(list->probability == 0.24f);
    assert(list->header != NULL);
    skiplist_destroy(list);

    printf(GREEN "test_new_skiplist passed\n" RESET);
}

void test_skiplist_put_get()
{
    skiplist *list = new_skiplist(12, 0.24f);
    unsigned char key[] = "key";
    unsigned char value[] = "value";
    assert(skiplist_put(list, key, sizeof(key), value, sizeof(value), -1) == true);

    unsigned char *retrieved_value;
    size_t retrieved_value_size;
    assert(skiplist_get(list, key, sizeof(key), &retrieved_value, &retrieved_value_size) == true);
    assert(memcmp(retrieved_value, value, sizeof(value)) == 0);

    skiplist_destroy(list);

    printf(GREEN "test_skiplist_put_get passed\n" RESET);
}

void test_skiplist_delete()
{
    skiplist *list = new_skiplist(12, 0.24f);
    unsigned char key[] = "key";
    unsigned char value[] = "value";
    assert(skiplist_put(list, key, sizeof(key), value, sizeof(value), -1) == true);
    assert(skiplist_delete(list, key, sizeof(key)) == true);

    unsigned char *retrieved_value;
    size_t retrieved_value_size;
    assert(skiplist_get(list, key, sizeof(key), &retrieved_value, &retrieved_value_size) == false);

    skiplist_destroy(list);

    printf(GREEN "test_skiplist_delete passed\n" RESET);
}

void test_skiplist_clear()
{
    skiplist *list = new_skiplist(12, 0.24f);
    unsigned char key[] = "key";
    unsigned char value[] = "value";
    assert(skiplist_put(list, key, sizeof(key), value, sizeof(value), -1) == true);
    assert(skiplist_clear(list) == 0);

    unsigned char *retrieved_value;
    size_t retrieved_value_size;
    assert(skiplist_get(list, key, sizeof(key), &retrieved_value, &retrieved_value_size) == false);

    skiplist_destroy(list);

    printf(GREEN "test_skiplist_clear passed\n" RESET);
}

void test_skiplist_cursor()
{
    skiplist *list = new_skiplist(12, 0.24f);
    unsigned char key1[] = "key1";
    unsigned char value1[] = "value1";
    unsigned char key2[] = "key2";
    unsigned char value2[] = "value2";
    assert(skiplist_put(list, key1, sizeof(key1), value1, sizeof(value1), -1) == true);
    assert(skiplist_put(list, key2, sizeof(key2), value2, sizeof(value2), -1) == true);

    skiplist_cursor *cursor = skiplist_cursor_init(list);
    assert(cursor != NULL);
    assert(cursor->current != NULL);
    assert(memcmp(cursor->current->key, key1, sizeof(key1)) == 0);

    assert(skiplist_cursor_next(cursor) == true);
    assert(memcmp(cursor->current->key, key2, sizeof(key2)) == 0);

    assert(skiplist_cursor_prev(cursor) == true);
    assert(memcmp(cursor->current->key, key1, sizeof(key1)) == 0);

    skiplist_cursor_free(cursor);
    skiplist_destroy(list);

    printf(GREEN "test_skiplist_cursor passed\n" RESET);
}

void test_skiplist_ttl()
{
    skiplist *list = new_skiplist(12, 0.24f);
    unsigned char key[] = "key";
    unsigned char value[] = "value";
    time_t ttl = 1; /* 1 second TTL */

    assert(skiplist_put(list, key, sizeof(key), value, sizeof(value), time(NULL) + ttl) == true);

    unsigned char *retrieved_value;
    size_t retrieved_value_size;
    assert(skiplist_get(list, key, sizeof(key), &retrieved_value, &retrieved_value_size) == true);
    assert(memcmp(retrieved_value, value, sizeof(value)) == 0);

    /* wait for TTL to expire */
    sleep(ttl + 2);

    assert(skiplist_get(list, key, sizeof(key), &retrieved_value, &retrieved_value_size) == true);

    /* check if value is TOMBSTONE */
    assert(memcmp(retrieved_value, "\xEF\xBE\xAD\xDE", 4) == 0);

    skiplist_destroy(list);

    printf(GREEN "test_skiplist_ttl passed\n" RESET);
}

/* thread_data_t struct to pass arguments to the thread function */
typedef struct
{
    skiplist *list;
    int thread_id;
} thread_data_t;

void *thread_func(void *arg)
{
    thread_data_t *data = arg;
    skiplist *list = data->list;
    int thread_id = data->thread_id;

    for (int i = 0; i < CONCURRENT_NUM_OPERATIONS; i++)
    {
        unsigned char key[16];
        unsigned char value[16];
        snprintf((char *)key, sizeof(key), "key%d_%d", thread_id, i);
        snprintf((char *)value, sizeof(value), "value%d_%d", thread_id, i);

        skiplist_put(list, key, strlen((char *)key) + 1, value, strlen((char *)value) + 1, -1);

        unsigned char *retrieved_value;
        size_t retrieved_value_size;
        skiplist_get(list, key, strlen((char *)key) + 1, &retrieved_value, &retrieved_value_size);

        skiplist_delete(list, key, strlen((char *)key) + 1);
    }

    pthread_exit(NULL);
}

void test_skiplist_concurrency()
{
    skiplist *list = new_skiplist(12, 0.24f);
    pthread_t threads[CONCURRENT_NUM_THREADS];
    thread_data_t thread_data[CONCURRENT_NUM_THREADS];

    for (int i = 0; i < CONCURRENT_NUM_THREADS; i++)
    {
        thread_data[i].list = list;
        thread_data[i].thread_id = i;
        pthread_create(&threads[i], NULL, thread_func, (void *)&thread_data[i]);
    }

    for (int i = 0; i < CONCURRENT_NUM_THREADS; i++) pthread_join(threads[i], NULL);

    skiplist_destroy(list);

    printf(GREEN "test_skiplist_concurrency passed\n" RESET);
}

void test_skiplist_copy()
{
    skiplist *list = new_skiplist(12, 0.24f);
    unsigned char key1[] = "key1";
    unsigned char value1[] = "value1";
    unsigned char key2[] = "key2";
    unsigned char value2[] = "value2";
    assert(skiplist_put(list, key1, sizeof(key1), value1, sizeof(value1), -1) == true);
    assert(skiplist_put(list, key2, sizeof(key2), value2, sizeof(value2), -1) == true);

    skiplist *copied_list = skiplist_copy(list);
    assert(copied_list != NULL);

    unsigned char *retrieved_value;
    size_t retrieved_value_size;
    assert(skiplist_get(copied_list, key1, sizeof(key1), &retrieved_value, &retrieved_value_size) ==
           true);
    assert(memcmp(retrieved_value, value1, sizeof(value1)) == 0);
    assert(skiplist_get(copied_list, key2, sizeof(key2), &retrieved_value, &retrieved_value_size) ==
           true);
    assert(memcmp(retrieved_value, value2, sizeof(value2)) == 0);

    skiplist_destroy(list);
    skiplist_destroy(copied_list);

    printf(GREEN "test_skiplist_copy passed\n" RESET);
}

int main(void)
{
    test_skiplist_create_node();
    test_new_skiplist();
    test_skiplist_put_get();
    test_skiplist_delete();
    test_skiplist_clear();
    test_skiplist_cursor();
    test_skiplist_ttl();
    test_skiplist_concurrency();
    test_skiplist_copy();
    return 0;
}