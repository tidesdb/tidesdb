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

/**
 * queue_alloc_node
 * @param queue the queue to allocate the node from
 * @return the allocated node, or NULL on failure
 */
static inline queue_node_t *queue_alloc_node(queue_t *queue)
{
    queue_node_t *node = NULL;

    if (queue->node_pool)
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
 * @param queue the queue to return the node to
 * @param node the node to return
 */
static inline void queue_free_node(queue_t *queue, queue_node_t *node)
{
    if (queue->pool_size < queue->max_pool_size)
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
        node = NULL;
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
    if (queue == NULL) return -1;

    pthread_mutex_lock(&queue->lock);

    /* allocate from pool (must be inside lock) */
    queue_node_t *node = queue_alloc_node(queue);
    if (node == NULL)
    {
        pthread_mutex_unlock(&queue->lock);
        return -1;
    }

    node->data = data;
    node->next = NULL;

    if (queue->tail == NULL)
    {
        queue->head = node;
        atomic_store_explicit(&queue->atomic_head, node, memory_order_release);
        queue->tail = node;
    }
    else
    {
        /* add to end */
        queue->tail->next = node;
        queue->tail = node;
    }

    atomic_fetch_add_explicit(&queue->size, 1, memory_order_relaxed);

    /* signal waiting threads that queue is not empty */
    pthread_cond_signal(&queue->not_empty);

    pthread_mutex_unlock(&queue->lock);

    return 0;
}

void *queue_dequeue(queue_t *queue)
{
    if (queue == NULL) return NULL;

    pthread_mutex_lock(&queue->lock);

    if (queue->head == NULL)
    {
        /* queue is empty */
        pthread_mutex_unlock(&queue->lock);
        return NULL;
    }

    queue_node_t *node = queue->head;
    void *data = node->data;

    queue->head = node->next;
    atomic_store_explicit(&queue->atomic_head, node->next, memory_order_release);
    if (queue->head == NULL)
    {
        /* queue is now empty */
        queue->tail = NULL;
    }

    atomic_fetch_sub_explicit(&queue->size, 1, memory_order_relaxed);

    /* return node to pool */
    queue_free_node(queue, node);

    pthread_mutex_unlock(&queue->lock);

    return data;
}

void *queue_dequeue_wait(queue_t *queue)
{
    if (queue == NULL) return NULL;

    pthread_mutex_lock(&queue->lock);

    /* wait until queue is not empty or shutdown */
    while (queue->head == NULL && !queue->shutdown)
    {
        /* increment waiter count only when actually waiting */
        queue->waiter_count++;
        pthread_cond_wait(&queue->not_empty, &queue->lock);
        /* decrement waiter count after waking up */
        queue->waiter_count--;
    }

    /* always broadcast when waiter_count changes to wake queue_free if waiting */
    if (queue->waiter_count == 0)
    {
        pthread_cond_broadcast(&queue->not_empty);
    }

    /* if shutdown and no data, return NULL */
    if (queue->shutdown && queue->head == NULL)
    {
        pthread_mutex_unlock(&queue->lock);
        return NULL;
    }

    queue_node_t *node = queue->head;
    void *data = node->data;

    queue->head = node->next;
    atomic_store_explicit(&queue->atomic_head, node->next, memory_order_release);
    if (queue->head == NULL)
    {
        queue->tail = NULL;
    }

    atomic_fetch_sub_explicit(&queue->size, 1, memory_order_relaxed);

    /* return node to pool */
    queue_free_node(queue, node);

    pthread_mutex_unlock(&queue->lock);

    return data;
}

void *queue_peek(queue_t *queue)
{
    if (queue == NULL) return NULL;

    pthread_mutex_lock(&queue->lock);

    void *data = NULL;
    if (queue->head != NULL)
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
    if (queue == NULL) return -1;

    pthread_mutex_lock(&queue->lock);

    queue_node_t *current = queue->head;
    while (current != NULL)
    {
        queue_node_t *next = current->next;
        queue_free_node(queue, current); /* return to pool */
        current = next;
    }

    queue->head = NULL;
    queue->tail = NULL;
    atomic_store_explicit(&queue->size, 0, memory_order_relaxed);

    pthread_mutex_unlock(&queue->lock);

    return 0;
}

int queue_foreach(queue_t *queue, void (*fn)(void *data, void *context), void *context)
{
    if (queue == NULL || fn == NULL) return -1;

    pthread_mutex_lock(&queue->lock);

    int count = 0;
    queue_node_t *current = queue->head;
    while (current != NULL)
    {
        fn(current->data, context);
        count++;
        current = current->next;
    }

    pthread_mutex_unlock(&queue->lock);

    return count;
}

void *queue_peek_at(queue_t *queue, size_t index)
{
    if (!queue) return NULL;

    size_t size = atomic_load_explicit(&queue->size, memory_order_relaxed);
    if (index >= size)
    {
        return NULL;
    }

    queue_node_t *current = atomic_load_explicit(&queue->atomic_head, memory_order_acquire);
    for (size_t i = 0; i < index && current; i++)
    {
        current = current->next;
    }

    return current ? current->data : NULL;
}

void queue_free(queue_t *queue)
{
    if (queue == NULL) return;

    pthread_mutex_lock(&queue->lock);

    /* set shutdown flag and wake all waiting threads */
    queue->shutdown = 1;
    pthread_cond_broadcast(&queue->not_empty);

    /* clear the queue while holding the lock */
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

    while (queue->waiter_count > 0)
    {
        pthread_cond_wait(&queue->not_empty, &queue->lock);
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
    queue->size = 0;

    queue->shutdown = 1;
    pthread_cond_broadcast(&queue->not_empty);

    pthread_mutex_unlock(&queue->lock);

    pthread_mutex_destroy(&queue->lock);
    pthread_cond_destroy(&queue->not_empty);

    free(queue);
    queue = NULL;
}