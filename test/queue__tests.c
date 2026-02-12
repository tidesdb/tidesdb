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

    int cleanup_count = 0;
    int result = queue_foreach(queue, cleanup_callback, &cleanup_count);
    ASSERT_EQ(result, 5);
    ASSERT_EQ(cleanup_count, 5);

    /* clear the queue (items already freed by foreach) */
    queue_clear(queue);
    queue_free(queue);
}

void test_queue_null_handling(void)
{
    ASSERT_EQ(queue_size(NULL), 0);
    ASSERT_EQ(queue_is_empty(NULL), -1);
    ASSERT_EQ(queue_peek(NULL), NULL);
    ASSERT_EQ(queue_dequeue(NULL), NULL);
    queue_clear(NULL); /* should not crash */
    queue_free(NULL);  /* should not crash */
}

void test_queue_peek_at(void)
{
    queue_t *queue = queue_new();
    ASSERT_TRUE(queue != NULL);

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

    queue_shutdown(queue);

    pthread_join(waiter, NULL);

    queue_free(queue);

    pthread_mutex_destroy(&start_lock);
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

    pthread_t waiters[5];
    for (int i = 0; i < 5; i++)
    {
        pthread_create(&waiters[i], NULL, multi_waiter_thread, queue);
    }

    usleep(100000); /* let threads start waiting */

    /* enqueue 5 items, each waiter should get one */
    int values[5] = {10, 20, 30, 40, 50};
    for (int i = 0; i < 5; i++)
    {
        queue_enqueue(queue, &values[i]);
        usleep(10000);
    }

    for (int i = 0; i < 5; i++)
    {
        void *result;
        pthread_join(waiters[i], &result);
        ASSERT_TRUE(result != NULL);
    }

    ASSERT_EQ(queue_size(queue), 0);
    queue_free(queue);
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
}

void benchmark_queue_single_threaded()
{
    printf("\n");
    queue_t *queue = queue_new();
    const int num_ops = 1000000;

    /* benchmark enqueue */
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < num_ops; i++)
    {
        int *data = malloc(sizeof(int));
        *data = i;
        queue_enqueue(queue, data);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double enqueue_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    double enqueue_ops_per_sec = num_ops / enqueue_time;

    printf("  Enqueue %d items: %.2f M ops/sec (%.3f seconds)\n", num_ops,
           enqueue_ops_per_sec / 1e6, enqueue_time);

    /* benchmark dequeue */
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < num_ops; i++)
    {
        int *data = (int *)queue_dequeue(queue);
        if (data)
        {
            ASSERT_EQ(*data, i);
            free(data);
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double dequeue_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    double dequeue_ops_per_sec = num_ops / dequeue_time;

    printf("  Dequeue %d items: %.2f M ops/sec (%.3f seconds)\n", num_ops,
           dequeue_ops_per_sec / 1e6, dequeue_time);

    ASSERT_EQ(queue_is_empty(queue), 1);
    queue_free(queue);
}

typedef struct
{
    queue_t *queue;
    int num_ops;
    int thread_id;
    struct timespec *start_time;
} benchmark_producer_args_t;

typedef struct
{
    queue_t *queue;
    int expected_items;
    _Atomic int *items_consumed;
} benchmark_consumer_args_t;

static void *benchmark_producer(void *arg)
{
    benchmark_producer_args_t *args = (benchmark_producer_args_t *)arg;

    /* wait for all threads to be ready */
    while (args->start_time->tv_sec == 0)
    {
        usleep(100);
    }

    for (int i = 0; i < args->num_ops; i++)
    {
        int *data = malloc(sizeof(int));
        *data = args->thread_id * 1000000 + i;
        queue_enqueue(args->queue, data);
    }

    return NULL;
}

static void *benchmark_consumer(void *arg)
{
    benchmark_consumer_args_t *args = (benchmark_consumer_args_t *)arg;

    while (1)
    {
        int consumed = atomic_load(args->items_consumed);
        if (consumed >= args->expected_items)
        {
            break;
        }

        int *data = (int *)queue_dequeue(args->queue);
        if (data != NULL)
        {
            atomic_fetch_add(args->items_consumed, 1);
            free(data);
        }
        else
        {
            /* queue empty, yield */
            sched_yield();
        }
    }

    return NULL;
}

void benchmark_queue_concurrent_producers_consumers()
{
    printf("\n");
    const int num_producers = 4;
    const int num_consumers = 4;
    const int ops_per_producer = 100000;
    const int total_items = num_producers * ops_per_producer;

    queue_t *queue = queue_new();

    pthread_t *producers = malloc(num_producers * sizeof(pthread_t));
    pthread_t *consumers = malloc(num_consumers * sizeof(pthread_t));
    benchmark_producer_args_t *producer_args =
        malloc(num_producers * sizeof(benchmark_producer_args_t));
    benchmark_consumer_args_t *consumer_args =
        malloc(num_consumers * sizeof(benchmark_consumer_args_t));

    _Atomic int items_consumed = 0;
    struct timespec start_time = {0, 0};

    /* create producers */
    for (int i = 0; i < num_producers; i++)
    {
        producer_args[i].queue = queue;
        producer_args[i].num_ops = ops_per_producer;
        producer_args[i].thread_id = i;
        producer_args[i].start_time = &start_time;
        pthread_create(&producers[i], NULL, benchmark_producer, &producer_args[i]);
    }

    /* create consumers */
    for (int i = 0; i < num_consumers; i++)
    {
        consumer_args[i].queue = queue;
        consumer_args[i].expected_items = total_items;
        consumer_args[i].items_consumed = &items_consumed;
        pthread_create(&consumers[i], NULL, benchmark_consumer, &consumer_args[i]);
    }

    /* start timing */
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    start_time = start; /* signal threads to start */

    /* wait for all producers */
    for (int i = 0; i < num_producers; i++)
    {
        pthread_join(producers[i], NULL);
    }

    /* wait for all consumers */
    for (int i = 0; i < num_consumers; i++)
    {
        pthread_join(consumers[i], NULL);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    double ops_per_sec = total_items / elapsed;

    printf("  %d producers, %d consumers, %d items each\n", num_producers, num_consumers,
           ops_per_producer);
    printf("  Total throughput: %.2f M ops/sec (%.3f seconds)\n", ops_per_sec / 1e6, elapsed);
    printf("  Items consumed: %d/%d\n", atomic_load(&items_consumed), total_items);

    free(producers);
    free(consumers);
    free(producer_args);
    free(consumer_args);
    queue_free(queue);
}

typedef struct
{
    queue_t *queue;
    int num_ops;
    struct timespec *start_time;
} benchmark_mixed_args_t;

static void *benchmark_mixed_thread(void *arg)
{
    benchmark_mixed_args_t *args = (benchmark_mixed_args_t *)arg;

    /* wait for start signal */
    while (args->start_time->tv_sec == 0)
    {
        usleep(100);
    }

    for (int i = 0; i < args->num_ops; i++)
    {
        /* 50% enqueue, 50% dequeue */
        if (i % 2 == 0)
        {
            int *data = malloc(sizeof(int));
            *data = i;
            queue_enqueue(args->queue, data);
        }
        else
        {
            int *data = (int *)queue_dequeue(args->queue);
            if (data) free(data);
        }
    }

    return NULL;
}

void benchmark_queue_mixed_operations()
{
    printf("\n");
    const int num_threads = 8;
    const int ops_per_thread = 50000;

    queue_t *queue = queue_new();

    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    benchmark_mixed_args_t *args = malloc(num_threads * sizeof(benchmark_mixed_args_t));
    struct timespec start_time = {0, 0};

    for (int i = 0; i < num_threads; i++)
    {
        args[i].queue = queue;
        args[i].num_ops = ops_per_thread;
        args[i].start_time = &start_time;
        pthread_create(&threads[i], NULL, benchmark_mixed_thread, &args[i]);
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    start_time = start;

    for (int i = 0; i < num_threads; i++)
    {
        pthread_join(threads[i], NULL);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    double total_ops = num_threads * ops_per_thread;
    double ops_per_sec = total_ops / elapsed;

    printf("  %d threads, %d mixed ops each (50%% enqueue, 50%% dequeue)\n", num_threads,
           ops_per_thread);
    printf("  Total throughput: %.2f M ops/sec (%.3f seconds)\n", ops_per_sec / 1e6, elapsed);
    printf("  Final queue size: %zu\n", queue_size(queue));

    free(threads);
    free(args);
    queue_free_with_data(queue, free);
}

void benchmark_queue_scaling()
{
    printf("\n");
    const int ops_per_thread = 50000;
    int thread_counts[] = {1, 2, 4, 8, 16};
    int num_configs = sizeof(thread_counts) / sizeof(thread_counts[0]);

    printf("  Operations per thread: %d (enqueue only)\n", ops_per_thread);
    printf("  %-10s %-15s %-15s %-15s\n", "Threads", "Time (s)", "Ops/sec", "Speedup");

    double baseline_time = 0.0;

    for (int c = 0; c < num_configs; c++)
    {
        int num_threads = thread_counts[c];
        queue_t *queue = queue_new();

        pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
        benchmark_producer_args_t *args = malloc(num_threads * sizeof(benchmark_producer_args_t));
        struct timespec start_time = {0, 0};

        for (int i = 0; i < num_threads; i++)
        {
            args[i].queue = queue;
            args[i].num_ops = ops_per_thread;
            args[i].thread_id = i;
            args[i].start_time = &start_time;
            pthread_create(&threads[i], NULL, benchmark_producer, &args[i]);
        }

        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        start_time = start;

        for (int i = 0; i < num_threads; i++)
        {
            pthread_join(threads[i], NULL);
        }

        clock_gettime(CLOCK_MONOTONIC, &end);
        double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
        double ops_per_sec = (num_threads * ops_per_thread) / elapsed;
        double speedup = (c == 0) ? 1.0 : baseline_time / elapsed;
        if (c == 0) baseline_time = elapsed;

        printf("  %-10d %-15.4f %-15.0f %-15.2f x\n", num_threads, elapsed, ops_per_sec, speedup);

        free(threads);
        free(args);
        queue_free_with_data(queue, free);
    }
}

#define BENCH_FOREACH_PEEK_NUM_THREADS 4
#define BENCH_FOREACH_PEEK_QUEUE_SIZE  10000
#define BENCH_FOREACH_PEEK_ITERATIONS  500

typedef struct
{
    queue_t *queue;
    int iterations;
    struct timespec *start_time;
    _Atomic int *ready_count;
    int total_threads;
} benchmark_foreach_peek_args_t;

static void foreach_noop_callback(void *data, void *context)
{
    (void)data;
    _Atomic int *count = (_Atomic int *)context;
    atomic_fetch_add(count, 1);
}

static void *benchmark_foreach_thread(void *arg)
{
    benchmark_foreach_peek_args_t *args = (benchmark_foreach_peek_args_t *)arg;

    atomic_fetch_add(args->ready_count, 1);

    while (atomic_load(args->ready_count) < args->total_threads)
    {
        cpu_pause();
    }

    while (args->start_time->tv_sec == 0)
    {
        cpu_pause();
    }

    _Atomic int visit_count = 0;

    for (int i = 0; i < args->iterations; i++)
    {
        queue_foreach(args->queue, foreach_noop_callback, (void *)&visit_count);
    }

    return (void *)(uintptr_t)atomic_load(&visit_count);
}

static void *benchmark_peek_at_thread(void *arg)
{
    benchmark_foreach_peek_args_t *args = (benchmark_foreach_peek_args_t *)arg;
    size_t queue_sz = queue_size(args->queue);

    atomic_fetch_add(args->ready_count, 1);

    while (atomic_load(args->ready_count) < args->total_threads)
    {
        cpu_pause();
    }

    while (args->start_time->tv_sec == 0)
    {
        cpu_pause();
    }

    int success_count = 0;

    for (int i = 0; i < args->iterations; i++)
    {
        for (size_t idx = 0; idx < queue_sz; idx++)
        {
            void *data = queue_peek_at(args->queue, idx);
            if (data != NULL)
            {
                success_count++;
            }
        }
    }

    return (void *)(uintptr_t)success_count;
}

void benchmark_queue_foreach_peek_at_concurrent()
{
    printf("\n");
    queue_t *queue = queue_new();

    int *values = malloc(BENCH_FOREACH_PEEK_QUEUE_SIZE * sizeof(int));
    for (int i = 0; i < BENCH_FOREACH_PEEK_QUEUE_SIZE; i++)
    {
        values[i] = i;
        queue_enqueue(queue, &values[i]);
    }

    printf("  Queue size: %d, Iterations per thread: %d\n", BENCH_FOREACH_PEEK_QUEUE_SIZE,
           BENCH_FOREACH_PEEK_ITERATIONS);

    /* Benchmark queue_foreach with multiple threads */
    {
        pthread_t threads[BENCH_FOREACH_PEEK_NUM_THREADS];
        benchmark_foreach_peek_args_t args[BENCH_FOREACH_PEEK_NUM_THREADS];
        struct timespec start_time = {0, 0};
        _Atomic int ready_count = 0;

        for (int i = 0; i < BENCH_FOREACH_PEEK_NUM_THREADS; i++)
        {
            args[i].queue = queue;
            args[i].iterations = BENCH_FOREACH_PEEK_ITERATIONS;
            args[i].start_time = &start_time;
            args[i].ready_count = &ready_count;
            args[i].total_threads = BENCH_FOREACH_PEEK_NUM_THREADS;
            pthread_create(&threads[i], NULL, benchmark_foreach_thread, &args[i]);
        }

        while (atomic_load(&ready_count) < BENCH_FOREACH_PEEK_NUM_THREADS)
        {
            usleep(100);
        }

        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        start_time = start;

        long total_visits = 0;
        for (int i = 0; i < BENCH_FOREACH_PEEK_NUM_THREADS; i++)
        {
            void *result;
            pthread_join(threads[i], &result);
            total_visits += (long)(uintptr_t)result;
        }

        clock_gettime(CLOCK_MONOTONIC, &end);
        double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
        double total_foreach_calls =
            (double)BENCH_FOREACH_PEEK_NUM_THREADS * BENCH_FOREACH_PEEK_ITERATIONS;
        double ops_per_sec = total_foreach_calls / elapsed;

        printf("  queue_foreach: %d threads, %.2f M calls/sec (%.3f s), %ld total visits\n",
               BENCH_FOREACH_PEEK_NUM_THREADS, ops_per_sec / 1e6, elapsed, total_visits);
    }

    /* Benchmark queue_peek_at with multiple threads */
    {
        pthread_t threads[BENCH_FOREACH_PEEK_NUM_THREADS];
        benchmark_foreach_peek_args_t args[BENCH_FOREACH_PEEK_NUM_THREADS];
        struct timespec start_time = {0, 0};
        _Atomic int ready_count = 0;

        for (int i = 0; i < BENCH_FOREACH_PEEK_NUM_THREADS; i++)
        {
            args[i].queue = queue;
            args[i].iterations = BENCH_FOREACH_PEEK_ITERATIONS;
            args[i].start_time = &start_time;
            args[i].ready_count = &ready_count;
            args[i].total_threads = BENCH_FOREACH_PEEK_NUM_THREADS;
            pthread_create(&threads[i], NULL, benchmark_peek_at_thread, &args[i]);
        }

        while (atomic_load(&ready_count) < BENCH_FOREACH_PEEK_NUM_THREADS)
        {
            usleep(100);
        }

        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        start_time = start;

        long total_peeks = 0;
        for (int i = 0; i < BENCH_FOREACH_PEEK_NUM_THREADS; i++)
        {
            void *result;
            pthread_join(threads[i], &result);
            total_peeks += (long)(uintptr_t)result;
        }

        clock_gettime(CLOCK_MONOTONIC, &end);
        double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
        double total_peek_calls = (double)BENCH_FOREACH_PEEK_NUM_THREADS *
                                  BENCH_FOREACH_PEEK_ITERATIONS * BENCH_FOREACH_PEEK_QUEUE_SIZE;
        double ops_per_sec = total_peek_calls / elapsed;

        printf("  queue_peek_at: %d threads, %.2f M calls/sec (%.3f s), %ld successful peeks\n",
               BENCH_FOREACH_PEEK_NUM_THREADS, ops_per_sec / 1e6, elapsed, total_peeks);
    }

    free(values);
    queue_free(queue);
}

void benchmark_queue_foreach_large()
{
    printf("\n");
    queue_t *queue = queue_new();
    const int queue_sizes[] = {1000, 10000, 100000};
    const int num_sizes = 3;

    for (int s = 0; s < num_sizes; s++)
    {
        int sz = queue_sizes[s];

        /* populate queue */
        int *values = malloc(sz * sizeof(int));
        for (int i = 0; i < sz; i++)
        {
            values[i] = i;
            queue_enqueue(queue, &values[i]);
        }

        /* benchmark foreach */
        int iterations = (sz <= 1000) ? 10000 : (sz <= 10000) ? 1000 : 100;
        _Atomic int visit_count = 0;

        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);

        for (int i = 0; i < iterations; i++)
        {
            queue_foreach(queue, foreach_noop_callback, (void *)&visit_count);
        }

        clock_gettime(CLOCK_MONOTONIC, &end);
        double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
        double total_visits_d = (double)iterations * sz;
        double visits_per_sec = total_visits_d / elapsed;

        printf("  foreach (queue_size=%d, iters=%d): %.2f M visits/sec (%.3f s)\n", sz, iterations,
               visits_per_sec / 1e6, elapsed);

        queue_clear(queue);
        free(values);
    }

    queue_free(queue);
}

void benchmark_queue_roundtrip()
{
    printf("\n");
    queue_t *queue = queue_new();
    const int num_ops = 1000000;

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < num_ops; i++)
    {
        int *data = malloc(sizeof(int));
        *data = i;
        queue_enqueue(queue, data);
        int *out = (int *)queue_dequeue(queue);
        if (out) free(out);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    double ops_per_sec = num_ops / elapsed;

    printf("  Enqueue+Dequeue round-trip %d ops: %.2f M ops/sec (%.3f s)\n", num_ops,
           ops_per_sec / 1e6, elapsed);
    printf("  Final queue size: %zu\n", queue_size(queue));

    queue_free(queue);
}

void benchmark_queue_clear()
{
    printf("\n");
    queue_t *queue = queue_new();
    const int fill_sizes[] = {1000, 10000, 100000};
    const int num_sizes = 3;

    for (int s = 0; s < num_sizes; s++)
    {
        int sz = fill_sizes[s];
        int iterations = (sz <= 1000) ? 1000 : (sz <= 10000) ? 100 : 10;

        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);

        for (int iter = 0; iter < iterations; iter++)
        {
            for (int i = 0; i < sz; i++)
            {
                int *data = malloc(sizeof(int));
                *data = i;
                queue_enqueue(queue, data);
            }
            /* clear frees nodes but not data -- we already lost the pointers
             * so just use free_with_data pattern instead */
            queue_node_t *dummy_check = NULL;
            (void)dummy_check;
            /* we need to dequeue and free data to avoid leaks */
            while (queue_size(queue) > 0)
            {
                int *d = (int *)queue_dequeue(queue);
                if (d) free(d);
            }
        }

        clock_gettime(CLOCK_MONOTONIC, &end);
        double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
        double total_ops = (double)iterations * sz * 2; /* enqueue + dequeue */
        double ops_per_sec = total_ops / elapsed;

        printf("  Fill+Drain (size=%d, iters=%d): %.2f M ops/sec (%.3f s)\n", sz, iterations,
               ops_per_sec / 1e6, elapsed);
    }

    queue_free(queue);
}

void benchmark_queue_peek()
{
    printf("\n");
    queue_t *queue = queue_new();
    const int queue_size_val = 10000;
    const int num_peeks = 1000000;

    int *values = malloc(queue_size_val * sizeof(int));
    for (int i = 0; i < queue_size_val; i++)
    {
        values[i] = i;
        queue_enqueue(queue, &values[i]);
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < num_peeks; i++)
    {
        void *data = queue_peek(queue);
        (void)data;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    double ops_per_sec = num_peeks / elapsed;

    printf("  queue_peek %d ops: %.2f M ops/sec (%.3f s)\n", num_peeks, ops_per_sec / 1e6, elapsed);

    free(values);
    queue_free(queue);
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
    RUN_TEST(test_queue_node_pool, tests_passed);
    RUN_TEST(test_queue_multiple_waiters, tests_passed);
    RUN_TEST(test_queue_enqueue_null_data, tests_passed);
    RUN_TEST(test_queue_is_empty, tests_passed);
    RUN_TEST(test_queue_peek_at_boundary, tests_passed);
    RUN_TEST(test_queue_foreach_empty, tests_passed);
    RUN_TEST(benchmark_queue_single_threaded, tests_passed);
    RUN_TEST(benchmark_queue_concurrent_producers_consumers, tests_passed);
    RUN_TEST(benchmark_queue_mixed_operations, tests_passed);
    RUN_TEST(benchmark_queue_scaling, tests_passed);
    RUN_TEST(benchmark_queue_foreach_peek_at_concurrent, tests_passed);
    RUN_TEST(benchmark_queue_foreach_large, tests_passed);
    RUN_TEST(benchmark_queue_roundtrip, tests_passed);
    RUN_TEST(benchmark_queue_clear, tests_passed);
    RUN_TEST(benchmark_queue_peek, tests_passed);

    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
