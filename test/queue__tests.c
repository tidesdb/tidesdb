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
#include "../src/compat.h"
#include "../src/queue.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

void test_queue_new(void)
{
    queue_t *queue = queue_new();
    ASSERT_TRUE(queue != NULL);
    ASSERT_EQ(queue_size(queue), 0);
    ASSERT_EQ(queue_is_empty(queue), 1);
    queue_free(queue);
    printf(GREEN "test_queue_new passed\n" RESET);
}

void test_queue_enqueue_dequeue(void)
{
    queue_t *queue = queue_new();
    ASSERT_TRUE(queue != NULL);

    int data1 = 42;
    int data2 = 100;
    int data3 = 200;

    ASSERT_EQ(queue_enqueue(queue, &data1), 0);
    ASSERT_EQ(queue_size(queue), 1);
    ASSERT_EQ(queue_is_empty(queue), 0);

    ASSERT_EQ(queue_enqueue(queue, &data2), 0);
    ASSERT_EQ(queue_size(queue), 2);

    ASSERT_EQ(queue_enqueue(queue, &data3), 0);
    ASSERT_EQ(queue_size(queue), 3);

    int *result1 = (int *)queue_dequeue(queue);
    ASSERT_TRUE(result1 != NULL);
    ASSERT_EQ(*result1, 42);
    ASSERT_EQ(queue_size(queue), 2);

    int *result2 = (int *)queue_dequeue(queue);
    ASSERT_TRUE(result2 != NULL);
    ASSERT_EQ(*result2, 100);
    ASSERT_EQ(queue_size(queue), 1);

    int *result3 = (int *)queue_dequeue(queue);
    ASSERT_TRUE(result3 != NULL);
    ASSERT_EQ(*result3, 200);
    ASSERT_EQ(queue_size(queue), 0);
    ASSERT_EQ(queue_is_empty(queue), 1);

    void *result4 = queue_dequeue(queue);
    ASSERT_TRUE(result4 == NULL);

    queue_free(queue);
    printf(GREEN "test_queue_enqueue_dequeue passed\n" RESET);
}

void test_queue_peek(void)
{
    queue_t *queue = queue_new();
    ASSERT_TRUE(queue != NULL);

    ASSERT_TRUE(queue_peek(queue) == NULL);

    int data1 = 42;
    int data2 = 100;

    queue_enqueue(queue, &data1);
    int *peek1 = (int *)queue_peek(queue);
    ASSERT_TRUE(peek1 != NULL);
    ASSERT_EQ(*peek1, 42);
    ASSERT_EQ(queue_size(queue), 1);

    queue_enqueue(queue, &data2);
    int *peek2 = (int *)queue_peek(queue);
    ASSERT_TRUE(peek2 != NULL);
    ASSERT_EQ(*peek2, 42);
    ASSERT_EQ(queue_size(queue), 2);

    queue_dequeue(queue);
    int *peek3 = (int *)queue_peek(queue);
    ASSERT_TRUE(peek3 != NULL);
    ASSERT_EQ(*peek3, 100);

    queue_free(queue);
    printf(GREEN "test_queue_peek passed\n" RESET);
}

void test_queue_clear(void)
{
    queue_t *queue = queue_new();
    ASSERT_TRUE(queue != NULL);

    int data1 = 1, data2 = 2, data3 = 3;
    queue_enqueue(queue, &data1);
    queue_enqueue(queue, &data2);
    queue_enqueue(queue, &data3);
    ASSERT_EQ(queue_size(queue), 3);

    ASSERT_EQ(queue_clear(queue), 0);
    ASSERT_EQ(queue_size(queue), 0);
    ASSERT_EQ(queue_is_empty(queue), 1);

    queue_free(queue);
    printf(GREEN "test_queue_clear passed\n" RESET);
}

void test_queue_with_strings(void)
{
    queue_t *queue = queue_new();
    ASSERT_TRUE(queue != NULL);

    char *str1 = strdup("hello");
    char *str2 = strdup("world");
    char *str3 = strdup("test");

    queue_enqueue(queue, str1);
    queue_enqueue(queue, str2);
    queue_enqueue(queue, str3);

    char *result1 = (char *)queue_dequeue(queue);
    ASSERT_TRUE(strcmp(result1, "hello") == 0);
    free(result1);

    char *result2 = (char *)queue_dequeue(queue);
    ASSERT_TRUE(strcmp(result2, "world") == 0);
    free(result2);

    char *result3 = (char *)queue_dequeue(queue);
    ASSERT_TRUE(strcmp(result3, "test") == 0);
    free(result3);

    queue_free(queue);
    printf(GREEN "test_queue_with_strings passed\n" RESET);
}

void test_queue_free_with_data(void)
{
    queue_t *queue = queue_new();
    ASSERT_TRUE(queue != NULL);

    char *str1 = strdup("hello");
    char *str2 = strdup("world");
    char *str3 = strdup("test");

    queue_enqueue(queue, str1);
    queue_enqueue(queue, str2);
    queue_enqueue(queue, str3);

    queue_free_with_data(queue, free);
    printf(GREEN "test_queue_free_with_data passed\n" RESET);
}

typedef struct
{
    queue_t *queue;
    int num_items;
    int thread_id;
} producer_args_t;

typedef struct
{
    queue_t *queue;
    int expected_total;
    int *consumed_count;
    pthread_mutex_t *count_lock;
} consumer_args_t;

static void *producer_thread(void *arg)
{
    producer_args_t *args = (producer_args_t *)arg;

    for (int i = 0; i < args->num_items; i++)
    {
        int *data = malloc(sizeof(int));
        *data = args->thread_id * 1000 + i;
        queue_enqueue(args->queue, data);
        usleep(100);
    }

    return NULL;
}

static void *consumer_thread(void *arg)
{
    consumer_args_t *args = (consumer_args_t *)arg;

    while (1)
    {
        pthread_mutex_lock(args->count_lock);
        if (*args->consumed_count >= args->expected_total)
        {
            pthread_mutex_unlock(args->count_lock);
            break;
        }
        pthread_mutex_unlock(args->count_lock);

        int *data = (int *)queue_dequeue(args->queue);
        if (data != NULL)
        {
            pthread_mutex_lock(args->count_lock);
            (*args->consumed_count)++;
            pthread_mutex_unlock(args->count_lock);
            free(data);
        }
    }

    return NULL;
}

void test_queue_threaded(void)
{
    queue_t *queue = queue_new();
    ASSERT_TRUE(queue != NULL);

#define NUM_PRODUCERS      3
#define NUM_CONSUMERS      2
#define ITEMS_PER_PRODUCER 50

    const int expected_total = NUM_PRODUCERS * ITEMS_PER_PRODUCER;

    pthread_t producers[NUM_PRODUCERS];
    pthread_t consumers[NUM_CONSUMERS];
    producer_args_t producer_args[NUM_PRODUCERS];

    int consumed_count = 0;
    pthread_mutex_t count_lock;
    pthread_mutex_init(&count_lock, NULL);

    consumer_args_t consumer_args;
    consumer_args.queue = queue;
    consumer_args.expected_total = expected_total;
    consumer_args.consumed_count = &consumed_count;
    consumer_args.count_lock = &count_lock;

    for (int i = 0; i < NUM_CONSUMERS; i++)
    {
        pthread_create(&consumers[i], NULL, consumer_thread, &consumer_args);
    }

    for (int i = 0; i < NUM_PRODUCERS; i++)
    {
        producer_args[i].queue = queue;
        producer_args[i].num_items = ITEMS_PER_PRODUCER;
        producer_args[i].thread_id = i;
        pthread_create(&producers[i], NULL, producer_thread, &producer_args[i]);
    }

    for (int i = 0; i < NUM_PRODUCERS; i++)
    {
        pthread_join(producers[i], NULL);
    }

    for (int i = 0; i < NUM_CONSUMERS; i++)
    {
        pthread_join(consumers[i], NULL);
    }

    ASSERT_EQ(consumed_count, expected_total);
    ASSERT_EQ(queue_is_empty(queue), 1);

    pthread_mutex_destroy(&count_lock);
    queue_free(queue);
    printf(GREEN "test_queue_threaded passed\n" RESET);
}

static void *blocking_consumer_thread(void *arg)
{
    queue_t *queue = (queue_t *)arg;

    int *data = (int *)queue_dequeue_wait(queue);
    ASSERT_TRUE(data != NULL);
    ASSERT_EQ(*data, 42);
    free(data);

    return NULL;
}

void test_queue_dequeue_wait(void)
{
    queue_t *queue = queue_new();
    ASSERT_TRUE(queue != NULL);

    pthread_t consumer;
    pthread_create(&consumer, NULL, blocking_consumer_thread, queue);

    usleep(100000);

    int *data = malloc(sizeof(int));
    *data = 42;
    queue_enqueue(queue, data);

    pthread_join(consumer, NULL);

    queue_free(queue);
    printf(GREEN "test_queue_dequeue_wait passed\n" RESET);
}

void test_queue_large_volume(void)
{
    queue_t *queue = queue_new();
    ASSERT_TRUE(queue != NULL);

    const int num_items = 10000;

    for (int i = 0; i < num_items; i++)
    {
        int *data = malloc(sizeof(int));
        *data = i;
        ASSERT_EQ(queue_enqueue(queue, data), 0);
    }

    ASSERT_EQ(queue_size(queue), (size_t)num_items);

    for (int i = 0; i < num_items; i++)
    {
        int *data = (int *)queue_dequeue(queue);
        ASSERT_TRUE(data != NULL);
        ASSERT_EQ(*data, i);
        free(data);
    }

    ASSERT_EQ(queue_is_empty(queue), 1);
    queue_free(queue);
    printf(GREEN "test_queue_large_volume passed\n" RESET);
}

typedef struct
{
    int sum;
    int count;
} foreach_context_t;

static void sum_callback(void *data, void *context)
{
    int *value = (int *)data;
    foreach_context_t *ctx = (foreach_context_t *)context;
    ctx->sum += *value;
    ctx->count++;
}

void test_queue_foreach(void)
{
    queue_t *queue = queue_new();
    ASSERT_TRUE(queue != NULL);

    foreach_context_t ctx = {0, 0};
    int result = queue_foreach(queue, sum_callback, &ctx);
    ASSERT_EQ(result, 0);
    ASSERT_EQ(ctx.count, 0);
    ASSERT_EQ(ctx.sum, 0);

    int data1 = 10, data2 = 20, data3 = 30, data4 = 40;
    queue_enqueue(queue, &data1);
    queue_enqueue(queue, &data2);
    queue_enqueue(queue, &data3);
    queue_enqueue(queue, &data4);

    /* iterate and sum */
    ctx.sum = 0;
    ctx.count = 0;
    result = queue_foreach(queue, sum_callback, &ctx);
    ASSERT_EQ(result, 4);
    ASSERT_EQ(ctx.count, 4);
    ASSERT_EQ(ctx.sum, 100);

    /* verify items still in queue */
    ASSERT_EQ(queue_size(queue), 4);

    /* test with NULL callback */
    ASSERT_EQ(queue_foreach(queue, NULL, NULL), -1);

    /* test with NULL queue */
    ASSERT_EQ(queue_foreach(NULL, sum_callback, &ctx), -1);

    queue_free(queue);
    printf(GREEN "test_queue_foreach passed\n" RESET);
}

typedef struct cleanup_item_t
{
    int id;
    char *name;
} cleanup_item_t;

static void cleanup_callback(void *data, void *context)
{
    cleanup_item_t *item = (cleanup_item_t *)data;
    int *cleanup_count = (int *)context;

    if (item->name) free(item->name);
    free(item);
    (*cleanup_count)++;
}

void test_queue_foreach_cleanup(void)
{
    queue_t *queue = queue_new();
    ASSERT_TRUE(queue != NULL);

    /* create items that need cleanup */
    for (int i = 0; i < 5; i++)
    {
        cleanup_item_t *item = malloc(sizeof(cleanup_item_t));
        item->id = i;
        item->name = strdup("test_item");
        queue_enqueue(queue, item);
    }

    ASSERT_EQ(queue_size(queue), 5);

    /* cleanup all items using foreach */
    int cleanup_count = 0;
    int result = queue_foreach(queue, cleanup_callback, &cleanup_count);
    ASSERT_EQ(result, 5);
    ASSERT_EQ(cleanup_count, 5);

    /* clear the queue (items already freed by foreach) */
    queue_clear(queue);
    queue_free(queue);
    printf(GREEN "test_queue_foreach_cleanup passed\n" RESET);
}

void test_queue_null_handling(void)
{
    ASSERT_EQ(queue_size(NULL), 0);
    ASSERT_EQ(queue_is_empty(NULL), -1);
    ASSERT_EQ(queue_peek(NULL), NULL);
    ASSERT_EQ(queue_dequeue(NULL), NULL);
    queue_clear(NULL); /* should not crash */
    queue_free(NULL);  /* should not crash */
    printf(GREEN "test_queue_null_handling passed\n" RESET);
}

void test_queue_peek_at(void)
{
    queue_t *queue = queue_new();
    ASSERT_TRUE(queue != NULL);

    /* test empty queue */
    ASSERT_EQ(queue_peek_at(queue, 0), NULL);
    ASSERT_EQ(queue_peek_at(queue, 10), NULL);

    int data1 = 10, data2 = 20, data3 = 30, data4 = 40;
    queue_enqueue(queue, &data1);
    queue_enqueue(queue, &data2);
    queue_enqueue(queue, &data3);
    queue_enqueue(queue, &data4);

    /* peek at each index */
    ASSERT_EQ(*(int *)queue_peek_at(queue, 0), 10); /* oldest */
    ASSERT_EQ(*(int *)queue_peek_at(queue, 1), 20);
    ASSERT_EQ(*(int *)queue_peek_at(queue, 2), 30);
    ASSERT_EQ(*(int *)queue_peek_at(queue, 3), 40); /* newest */

    /* test out of bounds */
    ASSERT_EQ(queue_peek_at(queue, 4), NULL);
    ASSERT_EQ(queue_peek_at(queue, 100), NULL);

    /* verify queue unchanged */
    ASSERT_EQ(queue_size(queue), 4);

    /* test with NULL queue */
    ASSERT_EQ(queue_peek_at(NULL, 0), NULL);

    queue_free(queue);
    printf(GREEN "test_queue_peek_at passed\n" RESET);
}

typedef struct
{
    queue_t *queue;
    int *thread_started;
    pthread_mutex_t *start_lock;
} wait_thread_args_t;

static void *wait_and_expect_null_thread(void *arg)
{
    wait_thread_args_t *args = (wait_thread_args_t *)arg;

    /* signal that thread has started */
    pthread_mutex_lock(args->start_lock);
    *args->thread_started = 1;
    pthread_mutex_unlock(args->start_lock);

    /* this should return NULL when queue is freed */
    void *data = queue_dequeue_wait(args->queue);

    /* we expect NULL because queue was freed while waiting */
    ASSERT_TRUE(data == NULL);

    return NULL;
}

void test_queue_free_with_waiting_threads(void)
{
    queue_t *queue = queue_new();
    ASSERT_TRUE(queue != NULL);

    int thread_started = 0;
    pthread_mutex_t start_lock;
    pthread_mutex_init(&start_lock, NULL);

    wait_thread_args_t args = {
        .queue = queue, .thread_started = &thread_started, .start_lock = &start_lock};

    pthread_t waiter;
    pthread_create(&waiter, NULL, wait_and_expect_null_thread, &args);

    while (1)
    {
        pthread_mutex_lock(&start_lock);
        if (thread_started)
        {
            pthread_mutex_unlock(&start_lock);
            break;
        }
        pthread_mutex_unlock(&start_lock);
        usleep(1000);
    }

    queue_free(queue);

    pthread_join(waiter, NULL);

    pthread_mutex_destroy(&start_lock);
    printf(GREEN "test_queue_free_with_waiting_threads passed\n" RESET);
}

void test_queue_node_pool()
{
    queue_t *queue = queue_new();

    /* add and remove many items to populate node pool */
    for (int i = 0; i < 100; i++)
    {
        int *val = malloc(sizeof(int));
        *val = i;
        queue_enqueue(queue, val);
    }

    /* dequeue all, should populate node pool */
    for (int i = 0; i < 100; i++)
    {
        int *val = (int *)queue_dequeue(queue);
        ASSERT_TRUE(val != NULL);
        ASSERT_EQ(*val, i);
        free(val);
    }

    ASSERT_EQ(queue_size(queue), 0);

    /* re-enqueue, should reuse nodes from pool */
    for (int i = 0; i < 50; i++)
    {
        int *val = malloc(sizeof(int));
        *val = i * 2;
        queue_enqueue(queue, val);
    }

    ASSERT_EQ(queue_size(queue), 50);

    queue_free_with_data(queue, free);
    printf(GREEN "test_queue_node_pool passed\n" RESET);
}

void *multi_waiter_thread(void *arg)
{
    queue_t *queue = (queue_t *)arg;
    void *data = queue_dequeue_wait(queue);
    return data;
}

void test_queue_multiple_waiters()
{
    queue_t *queue = queue_new();

    /* start 5 waiting threads */
    pthread_t waiters[5];
    for (int i = 0; i < 5; i++)
    {
        pthread_create(&waiters[i], NULL, multi_waiter_thread, queue);
    }

    usleep(100000); /* Let threads start waiting */

    /* enqueue 5 items, each waiter should get one */
    int values[5] = {10, 20, 30, 40, 50};
    for (int i = 0; i < 5; i++)
    {
        queue_enqueue(queue, &values[i]);
        usleep(10000);
    }

    /* wait for all threads */
    for (int i = 0; i < 5; i++)
    {
        void *result;
        pthread_join(waiters[i], &result);
        ASSERT_TRUE(result != NULL);
    }

    ASSERT_EQ(queue_size(queue), 0);
    queue_free(queue);
    printf(GREEN "test_queue_multiple_waiters passed\n" RESET);
}

void test_queue_enqueue_null_data()
{
    queue_t *queue = queue_new();

    /* not allowed!!!! */
    ASSERT_EQ(queue_enqueue(queue, NULL), 0);
    ASSERT_EQ(queue_size(queue), 1);

    void *data = queue_dequeue(queue);
    ASSERT_EQ(data, NULL); /* NULL is valid data */

    queue_free(queue);
    printf(GREEN "test_queue_enqueue_null_data passed\n" RESET);
}

void test_queue_is_empty()
{
    queue_t *queue = queue_new();

    ASSERT_EQ(queue_is_empty(queue), 1);

    int v = 1;
    queue_enqueue(queue, &v);
    ASSERT_EQ(queue_is_empty(queue), 0);

    queue_dequeue(queue);
    ASSERT_EQ(queue_is_empty(queue), 1);

    queue_free(queue);
    printf(GREEN "test_queue_is_empty passed\n" RESET);
}

void test_queue_peek_at_boundary()
{
    queue_t *queue = queue_new();

    int values[10];
    for (int i = 0; i < 10; i++)
    {
        values[i] = i * 10;
        queue_enqueue(queue, &values[i]);
    }

    /* test boundaries */
    ASSERT_EQ(*(int *)queue_peek_at(queue, 0), 0);  /* first */
    ASSERT_EQ(*(int *)queue_peek_at(queue, 9), 90); /* last */
    ASSERT_EQ(queue_peek_at(queue, 10), NULL);      /* out of bounds */
    ASSERT_EQ(queue_peek_at(queue, 100), NULL);     /* way out of bounds */

    queue_free(queue);
    printf(GREEN "test_queue_peek_at_boundary passed\n" RESET);
}

void test_queue_foreach_empty()
{
    queue_t *queue = queue_new();

    foreach_context_t ctx = {0, 0};
    int result = queue_foreach(queue, sum_callback, &ctx);
    ASSERT_EQ(result, 0);
    ASSERT_EQ(ctx.count, 0);
    ASSERT_EQ(ctx.sum, 0);

    queue_free(queue);
    printf(GREEN "test_queue_foreach_empty passed\n" RESET);
}

int main(void)
{
    RUN_TEST(test_queue_new, tests_passed);
    RUN_TEST(test_queue_enqueue_dequeue, tests_passed);
    RUN_TEST(test_queue_peek, tests_passed);
    RUN_TEST(test_queue_clear, tests_passed);
    RUN_TEST(test_queue_with_strings, tests_passed);
    RUN_TEST(test_queue_free_with_data, tests_passed);
    RUN_TEST(test_queue_dequeue_wait, tests_passed);
    RUN_TEST(test_queue_threaded, tests_passed);
    RUN_TEST(test_queue_large_volume, tests_passed);
    RUN_TEST(test_queue_foreach, tests_passed);
    RUN_TEST(test_queue_foreach_cleanup, tests_passed);
    RUN_TEST(test_queue_null_handling, tests_passed);
    RUN_TEST(test_queue_peek_at, tests_passed);
    RUN_TEST(test_queue_free_with_waiting_threads, tests_passed);

    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
