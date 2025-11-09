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
#include "queue.h"

#include "compat.h"

queue_t *queue_new(void)
{
    queue_t *queue = (queue_t *)malloc(sizeof(queue_t));
    if (queue == NULL) return NULL;

    queue->head = NULL;
    queue->tail = NULL;
    queue->size = 0;
    queue->shutdown = 0;

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

    queue_node_t *node = (queue_node_t *)malloc(sizeof(queue_node_t));
    if (node == NULL) return -1;

    node->data = data;
    node->next = NULL;

    pthread_mutex_lock(&queue->lock);

    if (queue->tail == NULL)
    {
        /* queue is empty */
        queue->head = node;
        queue->tail = node;
    }
    else
    {
        /* add to end */
        queue->tail->next = node;
        queue->tail = node;
    }

    queue->size++;

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
    if (queue->head == NULL)
    {
        /* queue is now empty */
        queue->tail = NULL;
    }

    queue->size--;

    pthread_mutex_unlock(&queue->lock);

    free(node);
    return data;
}

void *queue_dequeue_wait(queue_t *queue)
{
    if (queue == NULL) return NULL;

    pthread_mutex_lock(&queue->lock);

    /* wait until queue is not empty or shutdown */
    while (queue->head == NULL && !queue->shutdown)
    {
        pthread_cond_wait(&queue->not_empty, &queue->lock);
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
    if (queue->head == NULL)
    {
        queue->tail = NULL;
    }

    queue->size--;

    pthread_mutex_unlock(&queue->lock);

    free(node);
    return data;
}

void *queue_dequeue_timeout(queue_t *queue, int timeout_ms)
{
    if (queue == NULL) return NULL;

    pthread_mutex_lock(&queue->lock);

    if (queue->head == NULL)
    {
        /* calculate absolute timeout */
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);

        ts.tv_sec += timeout_ms / 1000;
        ts.tv_nsec += (timeout_ms % 1000) * 1000000L;

        /* handle nanosecond overflow */
        if (ts.tv_nsec >= 1000000000L)
        {
            ts.tv_sec += 1;
            ts.tv_nsec -= 1000000000L;
        }

        /* wait with timeout */
        int result = pthread_cond_timedwait(&queue->not_empty, &queue->lock, &ts);
        if (result == ETIMEDOUT || queue->head == NULL)
        {
            pthread_mutex_unlock(&queue->lock);
            return NULL;
        }
    }

    queue_node_t *node = queue->head;
    void *data = node->data;

    queue->head = node->next;
    if (queue->head == NULL)
    {
        queue->tail = NULL;
    }

    queue->size--;

    pthread_mutex_unlock(&queue->lock);

    free(node);
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

    pthread_mutex_lock(&queue->lock);
    size_t size = queue->size;
    pthread_mutex_unlock(&queue->lock);

    return size;
}

int queue_is_empty(queue_t *queue)
{
    if (queue == NULL) return -1;

    pthread_mutex_lock(&queue->lock);
    int empty = (queue->head == NULL) ? 1 : 0;
    pthread_mutex_unlock(&queue->lock);

    return empty;
}

int queue_clear(queue_t *queue)
{
    if (queue == NULL) return -1;

    pthread_mutex_lock(&queue->lock);

    queue_node_t *current = queue->head;
    while (current != NULL)
    {
        queue_node_t *next = current->next;
        free(current);
        current = next;
    }

    queue->head = NULL;
    queue->tail = NULL;
    queue->size = 0;

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

    pthread_mutex_lock(&queue->lock);

    if (index >= queue->size)
    {
        pthread_mutex_unlock(&queue->lock);
        return NULL;
    }

    queue_node_t *current = queue->head;
    for (size_t i = 0; i < index && current; i++)
    {
        current = current->next;
    }

    void *data = current ? current->data : NULL;

    pthread_mutex_unlock(&queue->lock);

    return data;
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

    queue->head = NULL;
    queue->tail = NULL;
    queue->size = 0;

    pthread_mutex_unlock(&queue->lock);

    /* small delay to allow waiting threads to exit their wait */
    /* this is a workaround for the race where threads may still be in pthread_cond_wait */
    struct timespec ts = {0, 1000000}; /* 1ms */
    nanosleep(&ts, NULL);

    pthread_mutex_destroy(&queue->lock);
    pthread_cond_destroy(&queue->not_empty);

    free(queue);
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

    queue->head = NULL;
    queue->tail = NULL;
    queue->size = 0;

    queue->shutdown = 1;
    pthread_cond_broadcast(&queue->not_empty);

    pthread_mutex_unlock(&queue->lock);

    pthread_mutex_destroy(&queue->lock);
    pthread_cond_destroy(&queue->not_empty);

    free(queue);
}
