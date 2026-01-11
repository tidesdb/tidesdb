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
#include "queue.h"

#include "compat.h"

/* branch prediction hints for hot paths */
#if defined(__GNUC__) || defined(__clang__)
#define QUEUE_LIKELY(x)   __builtin_expect(!!(x), 1)
#define QUEUE_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define QUEUE_LIKELY(x)   (x)
#define QUEUE_UNLIKELY(x) (x)
#endif

#define QUEUE_WAIT_TIMEOUT_NS 100000000  /* 100ms in nanoseconds */
#define QUEUE_NS_PER_SEC      1000000000 /* nanoseconds per second */

/**
 * queue_alloc_node
 * allocate a node from pool or heap
 * @param queue the queue to allocate the node from
 * @return the allocated node, or NULL on failure
 */
static inline queue_node_t *queue_alloc_node(queue_t *queue)
{
    queue_node_t *node = NULL;

    /* we check pool first (common case) */
    if (QUEUE_LIKELY(queue->node_pool != NULL))
    {
        node = queue->node_pool;
        queue->node_pool = node->next;
        queue->pool_size--;
    }
    else
    {
        node = (queue_node_t *)malloc(sizeof(queue_node_t));
    }

    return node;
}

/**
 * queue_free_node
 * return node to pool or free it
 * @param queue the queue to return the node to
 * @param node the node to return
 */
static inline void queue_free_node(queue_t *queue, queue_node_t *node)
{
    if (QUEUE_LIKELY(queue->pool_size < queue->max_pool_size))
    {
        /* return to pool */
        node->next = queue->node_pool;
        queue->node_pool = node;
        queue->pool_size++;
    }
    else
    {
        /* pool full, actually free */
        free(node);
    }
}

queue_t *queue_new(void)
{
    queue_t *queue = (queue_t *)malloc(sizeof(queue_t));
    if (queue == NULL) return NULL;

    queue->head = NULL;
    atomic_store(&queue->atomic_head, NULL);
    queue->tail = NULL;
    atomic_store_explicit(&queue->size, 0, memory_order_relaxed);
    queue->shutdown = 0;
    queue->waiter_count = 0;
    queue->node_pool = NULL;
    queue->pool_size = 0;
    queue->max_pool_size = QUEUE_MAX_POOL_SIZE;

    if (pthread_mutex_init(&queue->lock, NULL) != 0)
    {
        free(queue);
        return NULL;
    }

    if (pthread_cond_init(&queue->not_empty, NULL) != 0)
    {
        pthread_mutex_destroy(&queue->lock);
        free(queue);
        return NULL;
    }

    return queue;
}

int queue_enqueue(queue_t *queue, void *data)
{
    if (QUEUE_UNLIKELY(queue == NULL)) return -1;

    pthread_mutex_lock(&queue->lock);

    queue_node_t *node = queue_alloc_node(queue);
    if (QUEUE_UNLIKELY(node == NULL))
    {
        pthread_mutex_unlock(&queue->lock);
        return -1;
    }

    node->data = data;
    node->next = NULL;

    if (QUEUE_UNLIKELY(queue->tail == NULL))
    {
        queue->head = node;
        atomic_store_explicit(&queue->atomic_head, node, memory_order_release);
        queue->tail = node;
    }
    else
    {
        /* we add to end (common case) */
        queue->tail->next = node;
        queue->tail = node;
    }

    atomic_fetch_add_explicit(&queue->size, 1, memory_order_relaxed);

    /* signal waiting threads that queue is not empty */
    pthread_cond_signal(&queue->not_empty);

    pthread_mutex_unlock(&queue->lock);

    return 0;
}

/**
 * queue_dequeue_internal
 * internal helper for dequeue logic (lock must be held)
 * @param queue the queue
 * @return pointer to dequeued data, NULL if queue is empty
 */
static inline void *queue_dequeue_internal(queue_t *queue)
{
    if (QUEUE_UNLIKELY(queue->head == NULL))
    {
        return NULL;
    }

    queue_node_t *node = queue->head;
    void *data = node->data;

    queue->head = node->next;
    atomic_store_explicit(&queue->atomic_head, node->next, memory_order_release);

    /* optimization: check if queue became empty */
    if (QUEUE_UNLIKELY(queue->head == NULL))
    {
        queue->tail = NULL;
    }

    atomic_fetch_sub_explicit(&queue->size, 1, memory_order_relaxed);

    /* return node to pool */
    queue_free_node(queue, node);

    return data;
}

void *queue_dequeue(queue_t *queue)
{
    if (QUEUE_UNLIKELY(queue == NULL)) return NULL;

    pthread_mutex_lock(&queue->lock);
    void *data = queue_dequeue_internal(queue);
    pthread_mutex_unlock(&queue->lock);

    return data;
}

void *queue_dequeue_wait(queue_t *queue)
{
    if (QUEUE_UNLIKELY(queue == NULL)) return NULL;

    pthread_mutex_lock(&queue->lock);

    queue->waiter_count++;

    while (queue->head == NULL && !queue->shutdown)
    {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += QUEUE_WAIT_TIMEOUT_NS;
        if (ts.tv_nsec >= QUEUE_NS_PER_SEC)
        {
            ts.tv_sec += 1;
            ts.tv_nsec -= QUEUE_NS_PER_SEC;
        }
        pthread_cond_timedwait(&queue->not_empty, &queue->lock, &ts);
    }

    queue->waiter_count--;

    /* we must always broadcast when waiter_count changes to wake queue_free if waiting */
    if (queue->waiter_count == 0)
    {
        pthread_cond_broadcast(&queue->not_empty);
    }

    /* if shutdown and no data, return NULL */
    if (QUEUE_UNLIKELY(queue->shutdown && queue->head == NULL))
    {
        pthread_mutex_unlock(&queue->lock);
        return NULL;
    }

    /* use internal helper to avoid code duplication */
    void *data = queue_dequeue_internal(queue);

    pthread_mutex_unlock(&queue->lock);

    return data;
}

void *queue_peek(queue_t *queue)
{
    if (QUEUE_UNLIKELY(queue == NULL)) return NULL;

    pthread_mutex_lock(&queue->lock);

    void *data = NULL;
    if (QUEUE_LIKELY(queue->head != NULL))
    {
        data = queue->head->data;
    }

    pthread_mutex_unlock(&queue->lock);

    return data;
}

size_t queue_size(queue_t *queue)
{
    if (queue == NULL) return 0;

    return atomic_load_explicit(&queue->size, memory_order_relaxed);
}

int queue_is_empty(queue_t *queue)
{
    if (queue == NULL) return -1;

    return (atomic_load_explicit(&queue->size, memory_order_relaxed) == 0) ? 1 : 0;
}

int queue_clear(queue_t *queue)
{
    if (QUEUE_UNLIKELY(queue == NULL)) return -1;

    pthread_mutex_lock(&queue->lock);

    /* we batch return nodes to pool for better cache locality */
    queue_node_t *current = queue->head;
    queue_node_t *batch_head = NULL;
    queue_node_t *batch_tail = NULL;
    size_t batch_count = 0;

    while (current != NULL)
    {
        queue_node_t *next = current->next;

        if (batch_count < queue->max_pool_size - queue->pool_size)
        {
            if (batch_head == NULL)
            {
                batch_head = current;
                batch_tail = current;
            }
            else if (batch_tail != NULL)
            {
                batch_tail->next = current;
                batch_tail = current;
            }
            batch_count++;
        }
        else
        {
            /* pool would be full, thus we free directly */
            free(current);
        }

        current = next;
    }

    /* we attach batch to pool in one operation */
    if (batch_head != NULL && batch_tail != NULL)
    {
        batch_tail->next = queue->node_pool;
        queue->node_pool = batch_head;
        queue->pool_size += batch_count;
    }

    queue->head = NULL;
    queue->tail = NULL;
    atomic_store_explicit(&queue->atomic_head, NULL, memory_order_release);
    atomic_store_explicit(&queue->size, 0, memory_order_relaxed);

    pthread_mutex_unlock(&queue->lock);

    return 0;
}

int queue_foreach(queue_t *queue, void (*fn)(void *data, void *context), void *context)
{
    if (QUEUE_UNLIKELY(queue == NULL)) return -1;
    if (QUEUE_UNLIKELY(fn == NULL)) return -1;

    pthread_mutex_lock(&queue->lock);

    int count = 0;
    const queue_node_t *current = queue->head;
    while (QUEUE_LIKELY(current != NULL))
    {
        fn(current->data, context);
        count++;
        current = current->next;
    }

    pthread_mutex_unlock(&queue->lock);

    return count;
}

void *queue_peek_at(queue_t *queue, const size_t index)
{
    if (QUEUE_UNLIKELY(!queue)) return NULL;

    pthread_mutex_lock(&queue->lock);

    const queue_node_t *current = queue->head;
    for (size_t i = 0; i < index && QUEUE_LIKELY(current != NULL); i++)
    {
        current = current->next;
    }

    void *data = QUEUE_LIKELY(current != NULL) ? current->data : NULL;

    pthread_mutex_unlock(&queue->lock);

    return data;
}

void queue_free(queue_t *queue)
{
    if (queue == NULL) return;

    pthread_mutex_lock(&queue->lock);

    /* we set shutdown flag and wake all waiting threads */
    queue->shutdown = 1;
    pthread_cond_broadcast(&queue->not_empty);

    /* we clear the queue whilst holding the lock */
    queue_node_t *current = queue->head;
    while (current != NULL)
    {
        queue_node_t *next = current->next;
        free(current);
        current = next;
    }

    current = queue->node_pool;
    while (current != NULL)
    {
        queue_node_t *next = current->next;
        free(current);
        current = next;
    }

    queue->head = NULL;
    queue->tail = NULL;
    queue->node_pool = NULL;
    atomic_store_explicit(&queue->size, 0, memory_order_relaxed);

    /* wait for all waiting threads to exit before destroying primitives
     * use timed wait to handle NetBSD where signals can be missed */
    while (queue->waiter_count > 0)
    {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += QUEUE_WAIT_TIMEOUT_NS;
        if (ts.tv_nsec >= QUEUE_NS_PER_SEC)
        {
            ts.tv_sec += 1;
            ts.tv_nsec -= QUEUE_NS_PER_SEC;
        }
        pthread_cond_timedwait(&queue->not_empty, &queue->lock, &ts);
    }

    pthread_mutex_unlock(&queue->lock);
    pthread_mutex_destroy(&queue->lock);
    pthread_cond_destroy(&queue->not_empty);

    free(queue);
    queue = NULL;
}

void queue_free_with_data(queue_t *queue, void (*free_fn)(void *))
{
    if (queue == NULL) return;

    pthread_mutex_lock(&queue->lock);

    /* we set shutdown flag first and wake all waiting threads */
    queue->shutdown = 1;
    pthread_cond_broadcast(&queue->not_empty);

    queue_node_t *current = queue->head;
    while (current != NULL)
    {
        queue_node_t *next = current->next;
        if (free_fn != NULL && current->data != NULL)
        {
            free_fn(current->data);
        }
        free(current);
        current = next;
    }

    current = queue->node_pool;
    while (current != NULL)
    {
        queue_node_t *next = current->next;
        free(current);
        current = next;
    }

    queue->head = NULL;
    queue->tail = NULL;
    queue->node_pool = NULL;
    atomic_store_explicit(&queue->size, 0, memory_order_relaxed);

    /* we mustwait for all waiting threads to exit before destroying primitives
     * we use timed wait to handle BSD platforms where signals can be missed */
    while (queue->waiter_count > 0)
    {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += QUEUE_WAIT_TIMEOUT_NS;
        if (ts.tv_nsec >= QUEUE_NS_PER_SEC)
        {
            ts.tv_sec += 1;
            ts.tv_nsec -= QUEUE_NS_PER_SEC;
        }
        pthread_cond_timedwait(&queue->not_empty, &queue->lock, &ts);
    }

    pthread_mutex_unlock(&queue->lock);

    pthread_mutex_destroy(&queue->lock);
    pthread_cond_destroy(&queue->not_empty);

    free(queue);
    queue = NULL;
}