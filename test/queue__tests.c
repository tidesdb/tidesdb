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

    pthread_mutex_lock(&queue->wait_lock);
    atomic_store(&queue->shutdown, 1);
    pthread_cond_broadcast(&queue->not_empty);
    pthread_mutex_unlock(&queue->wait_lock);

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

typedef struct ref_counted_item_t
{
    int value;
    _Atomic(int) ref_count;
} ref_counted_item_t;

static void ref_item(void *item)
{
    ref_counted_item_t *rc_item = (ref_counted_item_t *)item;
    atomic_fetch_add(&rc_item->ref_count, 1);
}

static void unref_item(void *item)
{
    ref_counted_item_t *rc_item = (ref_counted_item_t *)item;
    int old_count = atomic_fetch_sub(&rc_item->ref_count, 1);
    if (old_count == 1)
    {
        free(rc_item);
    }
}

void test_queue_snapshot_with_refs()
{
    queue_t *queue = queue_new();
    ASSERT_TRUE(queue != NULL);

    /* test with empty queue */
    void **items = NULL;
    size_t count = 0;
    ASSERT_EQ(queue_snapshot_with_refs(queue, &items, &count, ref_item), 0);
    ASSERT_EQ(count, 0);
    ASSERT_TRUE(items == NULL);

    /* create ref-counted items */
    const int num_items = 5;
    ref_counted_item_t *rc_items[num_items];
    for (int i = 0; i < num_items; i++)
    {
        rc_items[i] = malloc(sizeof(ref_counted_item_t));
        rc_items[i]->value = i * 10;
        atomic_store(&rc_items[i]->ref_count, 1); /* initial ref */
        queue_enqueue(queue, rc_items[i]);
    }

    ASSERT_EQ(queue_size(queue), (size_t)num_items);

    /* take snapshot with refs */
    items = NULL;
    count = 0;
    ASSERT_EQ(queue_snapshot_with_refs(queue, &items, &count, ref_item), 0);
    ASSERT_EQ(count, (size_t)num_items);
    ASSERT_TRUE(items != NULL);

    /* verify snapshot contents and ref counts */
    for (size_t i = 0; i < count; i++)
    {
        ref_counted_item_t *item = (ref_counted_item_t *)items[i];
        ASSERT_EQ(item->value, (int)(i * 10));
        /* ref count should be 2: 1 from queue, 1 from snapshot */
        ASSERT_EQ(atomic_load(&item->ref_count), 2);
    }

    /* dequeue all items (releases queue's refs) */
    for (int i = 0; i < num_items; i++)
    {
        ref_counted_item_t *item = (ref_counted_item_t *)queue_dequeue(queue);
        ASSERT_TRUE(item != NULL);
        unref_item(item); /* release queue's ref */
    }

    ASSERT_EQ(queue_is_empty(queue), 1);

    /* items should still be valid because snapshot holds refs */
    for (size_t i = 0; i < count; i++)
    {
        ref_counted_item_t *item = (ref_counted_item_t *)items[i];
        ASSERT_EQ(item->value, (int)(i * 10));
        ASSERT_EQ(atomic_load(&item->ref_count), 1); /* only snapshot ref remains */
    }

    /* release snapshot refs */
    for (size_t i = 0; i < count; i++)
    {
        unref_item(items[i]);
    }
    free(items);

    /* test NULL parameter handling */
    ASSERT_EQ(queue_snapshot_with_refs(NULL, &items, &count, ref_item), -1);
    ASSERT_EQ(queue_snapshot_with_refs(queue, NULL, &count, ref_item), -1);
    ASSERT_EQ(queue_snapshot_with_refs(queue, &items, NULL, ref_item), -1);
    ASSERT_EQ(queue_snapshot_with_refs(queue, &items, &count, NULL), -1);

    queue_free(queue);
}

typedef struct snapshot_thread_args_t
{
    queue_t *queue;
    int thread_id;
    int num_snapshots;
    _Atomic(int) *total_snapshots_taken;
} snapshot_thread_args_t;

static void *snapshot_worker_thread(void *arg)
{
    snapshot_thread_args_t *args = (snapshot_thread_args_t *)arg;

    for (int i = 0; i < args->num_snapshots; i++)
    {
        void **items = NULL;
        size_t count = 0;

        int result = queue_snapshot_with_refs(args->queue, &items, &count, ref_item);
        if (result == 0)
        {
            atomic_fetch_add(args->total_snapshots_taken, 1);

            /* verify snapshot integrity */
            for (size_t j = 0; j < count; j++)
            {
                ref_counted_item_t *item = (ref_counted_item_t *)items[j];
                /* just verify we can read the value without crashing */
                volatile int val = item->value;
                (void)val;
            }

            /* release refs */
            for (size_t j = 0; j < count; j++)
            {
                unref_item(items[j]);
            }
            free(items);
        }

        usleep(1000); /* small delay between snapshots */
    }

    return NULL;
}

typedef struct enqueue_dequeue_thread_args_t
{
    queue_t *queue;
    int num_operations;
    int thread_id;
} enqueue_dequeue_thread_args_t;

static void *enqueue_dequeue_worker_thread(void *arg)
{
    enqueue_dequeue_thread_args_t *args = (enqueue_dequeue_thread_args_t *)arg;

    for (int i = 0; i < args->num_operations; i++)
    {
        /* enqueue a ref-counted item */
        ref_counted_item_t *item = malloc(sizeof(ref_counted_item_t));
        item->value = args->thread_id * 10000 + i;
        atomic_store(&item->ref_count, 1);
        queue_enqueue(args->queue, item);

        usleep(500);

        /* try to dequeue */
        ref_counted_item_t *dequeued = (ref_counted_item_t *)queue_dequeue(args->queue);
        if (dequeued)
        {
            unref_item(dequeued);
        }
    }

    return NULL;
}

void test_queue_snapshot_with_refs_concurrent()
{
    queue_t *queue = queue_new();
    ASSERT_TRUE(queue != NULL);

    /* pre-populate queue with some items */
    const int initial_items = 20;
    for (int i = 0; i < initial_items; i++)
    {
        ref_counted_item_t *item = malloc(sizeof(ref_counted_item_t));
        item->value = i;
        atomic_store(&item->ref_count, 1);
        queue_enqueue(queue, item);
    }

#define NUM_SNAPSHOT_THREADS        3
#define NUM_ENQUEUE_DEQUEUE_THREADS 2
#define SNAPSHOTS_PER_THREAD        10
#define OPS_PER_THREAD              20

    pthread_t snapshot_threads[NUM_SNAPSHOT_THREADS];
    pthread_t enqueue_dequeue_threads[NUM_ENQUEUE_DEQUEUE_THREADS];
    snapshot_thread_args_t snapshot_args[NUM_SNAPSHOT_THREADS];
    enqueue_dequeue_thread_args_t enqueue_dequeue_args[NUM_ENQUEUE_DEQUEUE_THREADS];

    _Atomic(int) total_snapshots_taken = 0;

    /* start snapshot threads */
    for (int i = 0; i < NUM_SNAPSHOT_THREADS; i++)
    {
        snapshot_args[i].queue = queue;
        snapshot_args[i].thread_id = i;
        snapshot_args[i].num_snapshots = SNAPSHOTS_PER_THREAD;
        snapshot_args[i].total_snapshots_taken = &total_snapshots_taken;
        pthread_create(&snapshot_threads[i], NULL, snapshot_worker_thread, &snapshot_args[i]);
    }

    /* start enqueue/dequeue threads */
    for (int i = 0; i < NUM_ENQUEUE_DEQUEUE_THREADS; i++)
    {
        enqueue_dequeue_args[i].queue = queue;
        enqueue_dequeue_args[i].num_operations = OPS_PER_THREAD;
        enqueue_dequeue_args[i].thread_id = i;
        pthread_create(&enqueue_dequeue_threads[i], NULL, enqueue_dequeue_worker_thread,
                       &enqueue_dequeue_args[i]);
    }

    /* wait for all threads */
    for (int i = 0; i < NUM_SNAPSHOT_THREADS; i++)
    {
        pthread_join(snapshot_threads[i], NULL);
    }

    for (int i = 0; i < NUM_ENQUEUE_DEQUEUE_THREADS; i++)
    {
        pthread_join(enqueue_dequeue_threads[i], NULL);
    }

    /* verify snapshots were taken */
    ASSERT_EQ(atomic_load(&total_snapshots_taken), NUM_SNAPSHOT_THREADS * SNAPSHOTS_PER_THREAD);

    /* cleanup remaining items in queue */
    ref_counted_item_t *item;
    while ((item = (ref_counted_item_t *)queue_dequeue(queue)) != NULL)
    {
        unref_item(item);
    }

    queue_free(queue);

#undef NUM_SNAPSHOT_THREADS
#undef NUM_ENQUEUE_DEQUEUE_THREADS
#undef SNAPSHOTS_PER_THREAD
#undef OPS_PER_THREAD
}

void test_queue_snapshot_with_refs_stress()
{
    queue_t *queue = queue_new();
    ASSERT_TRUE(queue != NULL);

    /* stress test: many items, concurrent snapshots and modifications */
    const int num_items = 100;
    for (int i = 0; i < num_items; i++)
    {
        ref_counted_item_t *item = malloc(sizeof(ref_counted_item_t));
        item->value = i * 100;
        atomic_store(&item->ref_count, 1);
        queue_enqueue(queue, item);
    }

    /* take multiple snapshots concurrently */
    const int num_concurrent_snapshots = 5;
    void **snapshots[num_concurrent_snapshots];
    size_t counts[num_concurrent_snapshots];

    /* all snapshots should succeed */
    for (int i = 0; i < num_concurrent_snapshots; i++)
    {
        snapshots[i] = NULL;
        counts[i] = 0;
        ASSERT_EQ(queue_snapshot_with_refs(queue, &snapshots[i], &counts[i], ref_item), 0);
        ASSERT_TRUE(counts[i] > 0);
        ASSERT_TRUE(snapshots[i] != NULL);
    }

    /* verify all snapshots have valid data */
    for (int i = 0; i < num_concurrent_snapshots; i++)
    {
        for (size_t j = 0; j < counts[i]; j++)
        {
            ref_counted_item_t *item = (ref_counted_item_t *)snapshots[i][j];
            /* verify ref count is at least 2 (queue + this snapshot) */
            ASSERT_TRUE(atomic_load(&item->ref_count) >= 2);
        }
    }

    /* dequeue all items from queue */
    ref_counted_item_t *item;
    int dequeued_count = 0;
    while ((item = (ref_counted_item_t *)queue_dequeue(queue)) != NULL)
    {
        unref_item(item);
        dequeued_count++;
    }
    ASSERT_EQ(dequeued_count, num_items);

    /* snapshots should still be valid even though queue is empty */
    for (int i = 0; i < num_concurrent_snapshots; i++)
    {
        for (size_t j = 0; j < counts[i]; j++)
        {
            ref_counted_item_t *item = (ref_counted_item_t *)snapshots[i][j];
            /* verify we can still read the value */
            volatile int val = item->value;
            (void)val;
        }
    }

    /* release all snapshot refs */
    for (int i = 0; i < num_concurrent_snapshots; i++)
    {
        for (size_t j = 0; j < counts[i]; j++)
        {
            unref_item(snapshots[i][j]);
        }
        free(snapshots[i]);
    }

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
    RUN_TEST(test_queue_snapshot_with_refs, tests_passed);
    RUN_TEST(test_queue_snapshot_with_refs_concurrent, tests_passed);
    RUN_TEST(test_queue_snapshot_with_refs_stress, tests_passed);

    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
