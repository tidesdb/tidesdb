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
#include "../src/buffer.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

/* eviction tracking */
static _Atomic(int) eviction_count = 0;
static _Atomic(int) eviction_sum = 0;

static void reset_eviction_counters(void)
{
    atomic_store(&eviction_count, 0);
    atomic_store(&eviction_sum, 0);
}

static void eviction_callback(void *data, void *ctx)
{
    (void)ctx;
    atomic_fetch_add(&eviction_count, 1);
    if (data != NULL)
    {
        int val = *(int *)data;
        atomic_fetch_add(&eviction_sum, val);
    }
}

static void eviction_free_callback(void *data, void *ctx)
{
    (void)ctx;
    atomic_fetch_add(&eviction_count, 1);
    if (data != NULL)
    {
        free(data);
    }
}

void test_buffer_create(void)
{
    buffer_t *buffer = NULL;

    ASSERT_EQ(buffer_new(&buffer, 10), 0);
    ASSERT_TRUE(buffer != NULL);
    ASSERT_EQ(buffer_capacity(buffer), 10);
    ASSERT_EQ(buffer_active_count(buffer), 0);
    buffer_free(buffer);

    buffer = NULL;
    reset_eviction_counters();
    ASSERT_EQ(buffer_new_with_eviction(&buffer, 5, eviction_callback, NULL), 0);
    ASSERT_TRUE(buffer != NULL);
    buffer_free(buffer);

    ASSERT_EQ(buffer_new(NULL, 10), -1);
    ASSERT_EQ(buffer_new(&buffer, 0), -1);
}

void test_buffer_acquire_release(void)
{
    buffer_t *buffer = NULL;
    ASSERT_EQ(buffer_new(&buffer, 5), 0);

    int values[5] = {10, 20, 30, 40, 50};
    uint32_t ids[5];

    /* acquire all slots */
    for (int i = 0; i < 5; i++)
    {
        ASSERT_EQ(buffer_acquire(buffer, &values[i], &ids[i]), 0);
        ASSERT_TRUE(ids[i] < 5);
        ASSERT_EQ(buffer_active_count(buffer), i + 1);
    }

    /* verify all occupied */
    for (int i = 0; i < 5; i++)
    {
        ASSERT_EQ(buffer_is_occupied(buffer, ids[i]), 1);
    }

    /* try acquire when full - should fail */
    uint32_t extra_id;
    buffer_set_retry_params(buffer, 10, 1); /* limit retries */
    ASSERT_EQ(buffer_try_acquire(buffer, &values[0], &extra_id), -1);
    ASSERT_EQ(extra_id, BUFFER_INVALID_ID);

    /* release one and acquire again */
    ASSERT_EQ(buffer_release(buffer, ids[2]), 0);
    ASSERT_EQ(buffer_active_count(buffer), 4);
    ASSERT_EQ(buffer_is_occupied(buffer, ids[2]), 0);

    int new_value = 100;
    uint32_t new_id;
    ASSERT_EQ(buffer_acquire(buffer, &new_value, &new_id), 0);
    ASSERT_EQ(buffer_active_count(buffer), 5);

    buffer_free(buffer);
}

void test_buffer_get(void)
{
    buffer_t *buffer = NULL;
    ASSERT_EQ(buffer_new(&buffer, 10), 0);

    int values[3] = {111, 222, 333};
    uint32_t ids[3];

    for (int i = 0; i < 3; i++)
    {
        ASSERT_EQ(buffer_acquire(buffer, &values[i], &ids[i]), 0);
    }

    /* get valid slots */
    for (int i = 0; i < 3; i++)
    {
        void *data;
        ASSERT_EQ(buffer_get(buffer, ids[i], &data), 0);
        ASSERT_EQ(data, &values[i]);
        ASSERT_EQ(*(int *)data, values[i]);
    }

    /* get invalid slot */
    void *data;
    ASSERT_EQ(buffer_get(buffer, 100, &data), -1); /* out of range */

    /* get free slot */
    uint32_t free_slot = 9;
    for (int i = 0; i < 3; i++)
    {
        if (ids[i] != 9) free_slot = 9;
    }

    ASSERT_EQ(buffer_get(buffer, free_slot, &data), -1);

    buffer_free(buffer);
}

void test_buffer_eviction_callback(void)
{
    buffer_t *buffer = NULL;
    reset_eviction_counters();

    ASSERT_EQ(buffer_new_with_eviction(&buffer, 5, eviction_callback, NULL), 0);

    int values[3] = {10, 20, 30};
    uint32_t ids[3];

    for (int i = 0; i < 3; i++)
    {
        ASSERT_EQ(buffer_acquire(buffer, &values[i], &ids[i]), 0);
    }

    /* release should trigger eviction */
    ASSERT_EQ(buffer_release(buffer, ids[0]), 0);
    ASSERT_EQ(atomic_load(&eviction_count), 1);
    ASSERT_EQ(atomic_load(&eviction_sum), 10);

    ASSERT_EQ(buffer_release(buffer, ids[1]), 0);
    ASSERT_EQ(atomic_load(&eviction_count), 2);
    ASSERT_EQ(atomic_load(&eviction_sum), 30);

    /* silent release should not trigger eviction */
    ASSERT_EQ(buffer_release_silent(buffer, ids[2]), 0);
    ASSERT_EQ(atomic_load(&eviction_count), 2);

    buffer_free(buffer);
}

void test_buffer_clear(void)
{
    buffer_t *buffer = NULL;
    reset_eviction_counters();

    ASSERT_EQ(buffer_new_with_eviction(&buffer, 10, eviction_callback, NULL), 0);

    int values[5] = {1, 2, 3, 4, 5};
    uint32_t ids[5];

    for (int i = 0; i < 5; i++)
    {
        ASSERT_EQ(buffer_acquire(buffer, &values[i], &ids[i]), 0);
    }
    ASSERT_EQ(buffer_active_count(buffer), 5);

    /* clear should release all and call eviction for each */
    ASSERT_EQ(buffer_clear(buffer), 0);
    ASSERT_EQ(buffer_active_count(buffer), 0);
    ASSERT_EQ(atomic_load(&eviction_count), 5);
    ASSERT_EQ(atomic_load(&eviction_sum), 15); /* 1+2+3+4+5 */

    buffer_free(buffer);
}

typedef struct
{
    int count;
    int sum;
} foreach_ctx_t;

static void foreach_callback(uint32_t id, void *data, void *ctx)
{
    (void)id;
    foreach_ctx_t *fctx = (foreach_ctx_t *)ctx;
    fctx->count++;
    if (data) fctx->sum += *(int *)data;
}

void test_buffer_foreach(void)
{
    buffer_t *buffer = NULL;
    ASSERT_EQ(buffer_new(&buffer, 10), 0);

    int values[5] = {10, 20, 30, 40, 50};
    uint32_t ids[5];

    for (int i = 0; i < 5; i++)
    {
        ASSERT_EQ(buffer_acquire(buffer, &values[i], &ids[i]), 0);
    }

    /* count and sum via foreach */
    foreach_ctx_t ctx = {0, 0};
    int visited = buffer_foreach(buffer, foreach_callback, &ctx);

    ASSERT_EQ(visited, 5);
    ASSERT_EQ(ctx.count, 5);
    ASSERT_EQ(ctx.sum, 150); /* 10+20+30+40+50 */

    buffer_free(buffer);
}

void test_buffer_generation(void)
{
    buffer_t *buffer = NULL;
    ASSERT_EQ(buffer_new(&buffer, 5), 0);

    int value = 42;
    uint32_t id1, id2;
    uint64_t gen1, gen2;

    ASSERT_EQ(buffer_acquire(buffer, &value, &id1), 0);
    ASSERT_EQ(buffer_get_generation(buffer, id1, &gen1), 0);

    /* validate with correct generation */
    ASSERT_EQ(buffer_validate(buffer, id1, gen1), 1);

    /* validate with wrong generation */
    ASSERT_EQ(buffer_validate(buffer, id1, gen1 + 100), 0);

    /* validate with 0 (skip generation check) */
    ASSERT_EQ(buffer_validate(buffer, id1, 0), 1);

    /* release and reacquire - if we get same slot, generation should increase */
    ASSERT_EQ(buffer_release(buffer, id1), 0);

    /* fill other slots first so we're more likely to reuse the same one */
    uint32_t temp_ids[4];
    for (int i = 0; i < 4; i++)
    {
        ASSERT_EQ(buffer_acquire(buffer, &value, &temp_ids[i]), 0);
    }
    /* release all temp slots */
    for (int i = 0; i < 4; i++)
    {
        buffer_release_silent(buffer, temp_ids[i]);
    }

    /* now acquire -- should get one of the freed slots */
    ASSERT_EQ(buffer_acquire(buffer, &value, &id2), 0);
    ASSERT_EQ(buffer_get_generation(buffer, id2, &gen2), 0);

    /* the generation for the NEW slot should be > 0 (incremented from initial) */
    ASSERT_TRUE(gen2 >= 1);

    /* if we got same slot, old generation is invalid */
    if (id2 == id1)
    {
        ASSERT_TRUE(gen2 > gen1);
        ASSERT_EQ(buffer_validate(buffer, id2, gen1), 0);
        ASSERT_EQ(buffer_validate(buffer, id2, gen2), 1);
    }

    buffer_free(buffer);
}

void test_buffer_null_validation(void)
{
    buffer_t *buffer = NULL;
    ASSERT_EQ(buffer_new(&buffer, 5), 0);

    /* test null parameters */
    ASSERT_EQ(buffer_acquire(NULL, (void *)1, NULL), -1);
    ASSERT_EQ(buffer_get(NULL, 0, NULL), -1);
    ASSERT_EQ(buffer_release(NULL, 0), -1);
    ASSERT_EQ(buffer_is_occupied(NULL, 0), -1);
    ASSERT_EQ(buffer_active_count(NULL), -1);
    ASSERT_EQ(buffer_capacity(NULL), -1);
    ASSERT_EQ(buffer_foreach(buffer, NULL, NULL), -1);

    uint32_t id;
    void *data;
    ASSERT_EQ(buffer_acquire(buffer, NULL, &id), 0); /* NULL data is allowed */
    ASSERT_EQ(buffer_get(buffer, id, &data), 0);
    ASSERT_EQ(data, NULL);

    buffer_free(buffer);
}

void test_buffer_slot_reuse(void)
{
    buffer_t *buffer = NULL;
    reset_eviction_counters();

    ASSERT_EQ(buffer_new_with_eviction(&buffer, 3, eviction_free_callback, NULL), 0);

    /* allocate and free repeatedly */
    for (int round = 0; round < 10; round++)
    {
        uint32_t ids[3];

        for (int i = 0; i < 3; i++)
        {
            int *val = (int *)malloc(sizeof(int));
            *val = round * 10 + i;
            ASSERT_EQ(buffer_acquire(buffer, val, &ids[i]), 0);
        }
        ASSERT_EQ(buffer_active_count(buffer), 3);

        for (int i = 0; i < 3; i++)
        {
            ASSERT_EQ(buffer_release(buffer, ids[i]), 0);
        }
        ASSERT_EQ(buffer_active_count(buffer), 0);
    }

    /* should have evicted 30 items (3 per round * 10 rounds) */
    ASSERT_EQ(atomic_load(&eviction_count), 30);

    buffer_free(buffer);
}

typedef struct
{
    buffer_t *buffer;
    int thread_id;
    int ops_per_thread;
    _Atomic(int) *success_count;
    _Atomic(int) *fail_count;
} thread_args_t;

void *concurrent_acquire_release(void *arg)
{
    thread_args_t *args = (thread_args_t *)arg;
    buffer_t *buffer = args->buffer;
    int ops = args->ops_per_thread;

    for (int i = 0; i < ops; i++)
    {
        int *value = (int *)malloc(sizeof(int));
        *value = args->thread_id * 10000 + i;

        uint32_t id;
        if (buffer_try_acquire(buffer, value, &id) == 0)
        {
            atomic_fetch_add(args->success_count, 1);

            /* small delay to increase contention */
            for (volatile int j = 0; j < 10; j++)
                ;

            /* verify we can get the value back */
            void *data;
            if (buffer_get(buffer, id, &data) == 0)
            {
                ASSERT_EQ(data, value);
            }

            buffer_release_silent(buffer, id);
            free(value);
        }
        else
        {
            atomic_fetch_add(args->fail_count, 1);
            free(value);
        }
    }

    return NULL;
}

void test_buffer_concurrent_acquire_release(void)
{
    buffer_t *buffer = NULL;
    assert(buffer_new(&buffer, 32) == 0);

    const int num_threads = 8;
    const int ops_per_thread = 10000;

    pthread_t *threads = (pthread_t *)malloc(num_threads * sizeof(pthread_t));
    thread_args_t *args = (thread_args_t *)malloc(num_threads * sizeof(thread_args_t));
    _Atomic(int) success_count = 0;
    _Atomic(int) fail_count = 0;

    for (int i = 0; i < num_threads; i++)
    {
        args[i].buffer = buffer;
        args[i].thread_id = i;
        args[i].ops_per_thread = ops_per_thread;
        args[i].success_count = &success_count;
        args[i].fail_count = &fail_count;
        pthread_create(&threads[i], NULL, concurrent_acquire_release, &args[i]);
    }

    for (int i = 0; i < num_threads; i++)
    {
        pthread_join(threads[i], NULL);
    }

    printf("\n  Successful ops: %d, Failed (buffer full): %d\n  ", atomic_load(&success_count),
           atomic_load(&fail_count));

    free(threads);
    free(args);

    assert(buffer_active_count(buffer) == 0);

    buffer_free(buffer);
}

void *concurrent_mixed_ops(void *arg)
{
    thread_args_t *args = (thread_args_t *)arg;
    buffer_t *buffer = args->buffer;
    int ops = args->ops_per_thread;

    uint32_t my_ids[10];
    int my_count = 0;

    for (int i = 0; i < ops; i++)
    {
        int op = rand() % 3;

        if (op == 0 && my_count < 10)
        {
            /* acquire */
            int *value = (int *)malloc(sizeof(int));
            *value = args->thread_id * 10000 + i;

            uint32_t id;
            if (buffer_try_acquire(buffer, value, &id) == 0)
            {
                my_ids[my_count++] = id;
                atomic_fetch_add(args->success_count, 1);
            }
            else
            {
                free(value);
            }
        }
        else if (op == 1 && my_count > 0)
        {
            /* release */
            int idx = rand() % my_count;
            uint32_t id = my_ids[idx];

            void *data;
            if (buffer_get(buffer, id, &data) == 0 && data != NULL)
            {
                free(data);
            }
            buffer_release_silent(buffer, id);

            my_ids[idx] = my_ids[--my_count];
            atomic_fetch_add(args->success_count, 1);
        }
        else if (my_count > 0)
        {
            /* get */
            int idx = rand() % my_count;
            void *data;
            if (buffer_get(buffer, my_ids[idx], &data) == 0)
            {
                atomic_fetch_add(args->success_count, 1);
            }
        }
    }

    for (int i = 0; i < my_count; i++)
    {
        void *data;
        if (buffer_get(buffer, my_ids[i], &data) == 0 && data != NULL)
        {
            free(data);
        }
        buffer_release_silent(buffer, my_ids[i]);
    }

    return NULL;
}

void test_buffer_concurrent_mixed(void)
{
    buffer_t *buffer = NULL;
    assert(buffer_new(&buffer, 64) == 0);

    const int num_threads = 8;
    const int ops_per_thread = 5000;

    pthread_t *threads = (pthread_t *)malloc(num_threads * sizeof(pthread_t));
    thread_args_t *args = (thread_args_t *)malloc(num_threads * sizeof(thread_args_t));
    _Atomic(int) success_count = 0;
    _Atomic(int) fail_count = 0;

    for (int i = 0; i < num_threads; i++)
    {
        args[i].buffer = buffer;
        args[i].thread_id = i;
        args[i].ops_per_thread = ops_per_thread;
        args[i].success_count = &success_count;
        args[i].fail_count = &fail_count;
        pthread_create(&threads[i], NULL, concurrent_mixed_ops, &args[i]);
    }

    for (int i = 0; i < num_threads; i++)
    {
        pthread_join(threads[i], NULL);
    }

    printf("\n  Total successful ops: %d\n  ", atomic_load(&success_count));

    free(threads);
    free(args);
    buffer_free(buffer);
}

typedef struct
{
    buffer_t *buffer;
    int thread_id;
    int iterations;
    _Atomic(int) *total_acquired;
} stress_args_t;

void *stress_worker(void *arg)
{
    stress_args_t *args = (stress_args_t *)arg;
    buffer_t *buffer = args->buffer;

    for (int i = 0; i < args->iterations; i++)
    {
        int value = args->thread_id * 100000 + i;
        uint32_t id;

        if (buffer_try_acquire(buffer, (void *)(intptr_t)value, &id) == 0)
        {
            atomic_fetch_add(args->total_acquired, 1);

            /* verify */
            void *data;
            assert(buffer_get(buffer, id, &data) == 0);
            assert((intptr_t)data == value);

            buffer_release_silent(buffer, id);
        }
    }

    return NULL;
}

void test_buffer_stress(void)
{
    const int num_threads = 16;
    const int iterations = 10000;
    const int capacity = 16;

    buffer_t *buffer = NULL;
    assert(buffer_new(&buffer, capacity) == 0); /* small buffer for high contention */

    pthread_t *threads = (pthread_t *)malloc(num_threads * sizeof(pthread_t));
    stress_args_t *args = (stress_args_t *)malloc(num_threads * sizeof(stress_args_t));
    _Atomic(int) total_acquired = 0;

    clock_t start = clock();

    for (int i = 0; i < num_threads; i++)
    {
        args[i].buffer = buffer;
        args[i].thread_id = i;
        args[i].iterations = iterations;
        args[i].total_acquired = &total_acquired;
        pthread_create(&threads[i], NULL, stress_worker, &args[i]);
    }

    for (int i = 0; i < num_threads; i++)
    {
        pthread_join(threads[i], NULL);
    }

    clock_t end = clock();
    double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
    int acquired = atomic_load(&total_acquired);

    printf("\n  High contention stress test:\n");
    printf("    %d threads, %d iterations each, 16 slots\n", num_threads, iterations);
    printf("    Total acquired: %d in %.3f seconds\n", acquired, elapsed);
    printf("    Throughput: %.2f M ops/sec\n  ", acquired / elapsed / 1000000.0);

    free(threads);
    free(args);
    buffer_free(buffer);
}

void benchmark_buffer_single_threaded(void)
{
    printf("\n");
    buffer_t *buffer = NULL;
    const int capacity = 1000;
    const int num_ops = 1000000;

    assert(buffer_new(&buffer, capacity) == 0);

    uint32_t *ids = (uint32_t *)malloc(capacity * sizeof(uint32_t));
    int idx = 0;

    /* benchmark acquire */
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < num_ops; i++)
    {
        int value = i;
        if (buffer_try_acquire(buffer, (void *)(intptr_t)value, &ids[idx]) == 0)
        {
            idx++;
            if (idx == capacity)
            {
                /* release all to make room */
                for (int j = 0; j < capacity; j++)
                {
                    buffer_release_silent(buffer, ids[j]);
                }
                idx = 0;
            }
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double acquire_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    double acquire_ops_per_sec = num_ops / acquire_time;

    printf("  Acquire/Release %d items: %.2f M ops/sec (%.3f seconds)\n", num_ops,
           acquire_ops_per_sec / 1e6, acquire_time);

    /* cleanup remaining */
    for (int j = 0; j < idx; j++)
    {
        buffer_release_silent(buffer, ids[j]);
    }

    free(ids);
    buffer_free(buffer);
}

typedef struct
{
    buffer_t *buffer;
    int thread_id;
    int num_ops;
    struct timespec *start_time;
    _Atomic(int) *ops_completed;
} benchmark_buffer_args_t;

static void *benchmark_buffer_worker(void *arg)
{
    benchmark_buffer_args_t *args = (benchmark_buffer_args_t *)arg;

    /* wait for start signal */
    while (args->start_time->tv_sec == 0)
    {
        usleep(100);
    }

    for (int i = 0; i < args->num_ops; i++)
    {
        int value = args->thread_id * 1000000 + i;
        uint32_t id;

        if (buffer_try_acquire(args->buffer, (void *)(intptr_t)value, &id) == 0)
        {
            /* verify */
            void *data;
            if (buffer_get(args->buffer, id, &data) == 0)
            {
                assert((intptr_t)data == value);
            }

            buffer_release_silent(args->buffer, id);
            atomic_fetch_add(args->ops_completed, 1);
        }
        else
        {
            /* buffer full, retry with small delay */
            cpu_pause();
            i--; /* retry this operation */
        }
    }

    return NULL;
}

void benchmark_buffer_concurrent_throughput(void)
{
    printf("\n");
    const int num_threads = 8;
    const int ops_per_thread = 50000;
    const int capacity = 256;

    buffer_t *buffer = NULL;
    assert(buffer_new(&buffer, capacity) == 0);

    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    benchmark_buffer_args_t *args = malloc(num_threads * sizeof(benchmark_buffer_args_t));
    _Atomic(int) ops_completed = 0;
    struct timespec start_time = {0, 0};

    for (int i = 0; i < num_threads; i++)
    {
        args[i].buffer = buffer;
        args[i].thread_id = i;
        args[i].num_ops = ops_per_thread;
        args[i].start_time = &start_time;
        args[i].ops_completed = &ops_completed;
        pthread_create(&threads[i], NULL, benchmark_buffer_worker, &args[i]);
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
    double ops_per_sec = (num_threads * ops_per_thread * 2.0) / elapsed;

    printf("  %d threads, %d ops each, %d slots\n", num_threads, ops_per_thread, capacity);
    printf("  Total throughput: %.2f M ops/sec (%.3f seconds)\n", ops_per_sec / 1e6, elapsed);
    printf("  Operations completed: %d/%d\n", ops_completed, num_threads * ops_per_thread);

    free(threads);
    free(args);
    buffer_free(buffer);
}

static void *benchmark_buffer_mixed_worker(void *arg)
{
    benchmark_buffer_args_t *args = (benchmark_buffer_args_t *)arg;
    uint32_t *my_slots = malloc(10 * sizeof(uint32_t));
    int my_count = 0;

    /* wait for start signal */
    while (args->start_time->tv_sec == 0)
    {
        usleep(100);
    }

    for (int i = 0; i < args->num_ops; i++)
    {
        int op = i % 3;

        if (op == 0 && my_count < 10)
        {
            /* acquire */
            int value = args->thread_id * 1000000 + i;
            uint32_t id;
            if (buffer_try_acquire(args->buffer, (void *)(intptr_t)value, &id) == 0)
            {
                my_slots[my_count++] = id;
                atomic_fetch_add(args->ops_completed, 1);
            }
        }
        else if (op == 1 && my_count > 0)
        {
            /* release */
            int idx = my_count - 1;
            buffer_release_silent(args->buffer, my_slots[idx]);
            my_count--;
            atomic_fetch_add(args->ops_completed, 1);
        }
        else if (my_count > 0)
        {
            /* get */
            void *data;
            if (buffer_get(args->buffer, my_slots[0], &data) == 0)
            {
                atomic_fetch_add(args->ops_completed, 1);
            }
        }
    }

    /* cleanup */
    for (int i = 0; i < my_count; i++)
    {
        buffer_release_silent(args->buffer, my_slots[i]);
    }

    free(my_slots);
    return NULL;
}

void benchmark_buffer_mixed_operations(void)
{
    printf("\n");
    const int num_threads = 8;
    const int ops_per_thread = 30000;
    const int capacity = 128;

    buffer_t *buffer = NULL;
    assert(buffer_new(&buffer, capacity) == 0);

    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    benchmark_buffer_args_t *args = malloc(num_threads * sizeof(benchmark_buffer_args_t));
    _Atomic(int) ops_completed = 0;
    struct timespec start_time = {0, 0};

    for (int i = 0; i < num_threads; i++)
    {
        args[i].buffer = buffer;
        args[i].thread_id = i;
        args[i].num_ops = ops_per_thread;
        args[i].start_time = &start_time;
        args[i].ops_completed = &ops_completed;
        pthread_create(&threads[i], NULL, benchmark_buffer_mixed_worker, &args[i]);
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
    int completed = atomic_load(&ops_completed);
    double ops_per_sec = completed / elapsed;

    printf("  %d threads, %d mixed ops each (acquire/release/get)\n", num_threads, ops_per_thread);
    printf("  Total throughput: %.2f M ops/sec (%.3f seconds)\n", ops_per_sec / 1e6, elapsed);
    printf("  Final active slots: %d\n", buffer_active_count(buffer));

    free(threads);
    free(args);
    buffer_free(buffer);
}

void benchmark_buffer_scaling(void)
{
    printf("\n");
    const int ops_per_thread = 50000;
    const int capacity = 512;
    int thread_counts[] = {1, 2, 4, 8, 16};
    int num_configs = sizeof(thread_counts) / sizeof(thread_counts[0]);

    printf("  Operations per thread: %d (acquire/release cycles)\n", ops_per_thread);
    printf("  Buffer capacity: %d slots\n", capacity);
    printf("  %-10s %-15s %-15s %-15s\n", "Threads", "Time (s)", "Ops/sec", "Speedup");

    double baseline_time = 0.0;

    for (int c = 0; c < num_configs; c++)
    {
        int num_threads = thread_counts[c];
        buffer_t *buffer = NULL;
        assert(buffer_new(&buffer, capacity) == 0);

        pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
        benchmark_buffer_args_t *args = malloc(num_threads * sizeof(benchmark_buffer_args_t));
        _Atomic(int) ops_completed = 0;
        struct timespec start_time = {0, 0};

        for (int i = 0; i < num_threads; i++)
        {
            args[i].buffer = buffer;
            args[i].thread_id = i;
            args[i].num_ops = ops_per_thread;
            args[i].start_time = &start_time;
            args[i].ops_completed = &ops_completed;
            pthread_create(&threads[i], NULL, benchmark_buffer_worker, &args[i]);
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
        double ops_per_sec = (num_threads * ops_per_thread * 2.0) / elapsed;
        double speedup = (c == 0) ? 1.0 : baseline_time / elapsed;
        if (c == 0) baseline_time = elapsed;

        printf("  %-10d %-15.4f %-15.0f %-15.2f x\n", num_threads, elapsed, ops_per_sec, speedup);

        free(threads);
        free(args);
        buffer_free(buffer);
    }
}

void benchmark_buffer_high_contention(void)
{
    printf("\n");
    const int num_threads = 16;
    const int ops_per_thread = 20000;
    const int capacity = 32; /* small buffer for high contention */

    buffer_t *buffer = NULL;
    assert(buffer_new(&buffer, capacity) == 0);

    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    benchmark_buffer_args_t *args = malloc(num_threads * sizeof(benchmark_buffer_args_t));
    _Atomic(int) ops_completed = 0;
    struct timespec start_time = {0, 0};

    for (int i = 0; i < num_threads; i++)
    {
        args[i].buffer = buffer;
        args[i].thread_id = i;
        args[i].num_ops = ops_per_thread;
        args[i].start_time = &start_time;
        args[i].ops_completed = &ops_completed;
        pthread_create(&threads[i], NULL, benchmark_buffer_worker, &args[i]);
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
    double ops_per_sec = (num_threads * ops_per_thread * 2.0) / elapsed;

    printf("  High contention: %d threads, %d slots\n", num_threads, capacity);
    printf("  Total throughput: %.2f M ops/sec (%.3f seconds)\n", ops_per_sec / 1e6, elapsed);
    printf("  Operations completed: %d/%d\n", ops_completed, num_threads * ops_per_thread);

    free(threads);
    free(args);
    buffer_free(buffer);
}

static void free_allocated_data(void *data, void *ctx)
{
    (void)ctx;
    if (data) free(data);
}

static void test_buffer_eviction_with_malloc(void)
{
    buffer_t *buffer = NULL;

    ASSERT_EQ(buffer_new_with_eviction(&buffer, 16, free_allocated_data, NULL), 0);
    ASSERT_TRUE(buffer != NULL);

    uint32_t ids[10];
    for (int i = 0; i < 10; i++)
    {
        int *entry = (int *)malloc(sizeof(int));
        ASSERT_TRUE(entry != NULL);
        *entry = i * 100;

        /* acquire slot and store entry */
        ASSERT_EQ(buffer_acquire(buffer, entry, &ids[i]), 0);
        ASSERT_NE(ids[i], BUFFER_INVALID_ID);
    }

    /* verify entries are stored */
    ASSERT_EQ(buffer_active_count(buffer), 10);

    for (int i = 0; i < 5; i++)
    {
        ASSERT_EQ(buffer_release(buffer, ids[i]), 0);
    }

    ASSERT_EQ(buffer_active_count(buffer), 5);

    buffer_free(buffer);
}

typedef struct
{
    uint64_t id;
    uint64_t snapshot_seq;
    void *data;
} test_entry_t;

static void free_test_entry(void *data, void *ctx)
{
    (void)ctx;
    if (data)
    {
        test_entry_t *entry = (test_entry_t *)data;
        if (entry->data) free(entry->data);
        free(entry);
    }
}

static void test_buffer_struct_eviction(void)
{
    buffer_t *buffer = NULL;

    ASSERT_EQ(buffer_new_with_eviction(&buffer, 32, free_test_entry, NULL), 0);
    ASSERT_TRUE(buffer != NULL);

    uint32_t ids[20];
    for (int i = 0; i < 20; i++)
    {
        test_entry_t *entry = (test_entry_t *)malloc(sizeof(test_entry_t));
        ASSERT_TRUE(entry != NULL);

        entry->id = i;
        entry->snapshot_seq = i * 1000;
        entry->data = malloc(64);
        ASSERT_TRUE(entry->data != NULL);

        ASSERT_EQ(buffer_acquire(buffer, entry, &ids[i]), 0);
    }

    ASSERT_EQ(buffer_active_count(buffer), 20);

    for (int i = 0; i < 10; i++)
    {
        ASSERT_EQ(buffer_release(buffer, ids[i]), 0);
    }

    ASSERT_EQ(buffer_active_count(buffer), 10);

    buffer_free(buffer);
}

int main(void)
{
    RUN_TEST(test_buffer_create, tests_passed);
    RUN_TEST(test_buffer_acquire_release, tests_passed);
    RUN_TEST(test_buffer_get, tests_passed);
    RUN_TEST(test_buffer_eviction_callback, tests_passed);
    RUN_TEST(test_buffer_clear, tests_passed);
    RUN_TEST(test_buffer_foreach, tests_passed);
    RUN_TEST(test_buffer_generation, tests_passed);
    RUN_TEST(test_buffer_null_validation, tests_passed);
    RUN_TEST(test_buffer_slot_reuse, tests_passed);
    RUN_TEST(test_buffer_concurrent_acquire_release, tests_passed);
    RUN_TEST(test_buffer_concurrent_mixed, tests_passed);
    RUN_TEST(test_buffer_eviction_with_malloc, tests_passed);
    RUN_TEST(test_buffer_struct_eviction, tests_passed);
    RUN_TEST(test_buffer_stress, tests_passed);
    RUN_TEST(benchmark_buffer_single_threaded, tests_passed);
    RUN_TEST(benchmark_buffer_concurrent_throughput, tests_passed);
    RUN_TEST(benchmark_buffer_mixed_operations, tests_passed);
    RUN_TEST(benchmark_buffer_scaling, tests_passed);
    RUN_TEST(benchmark_buffer_high_contention, tests_passed);

    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}