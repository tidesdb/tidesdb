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

#if defined(_WIN32) || defined(_WIN64)
queue *queue_new()
{
    queue *q = malloc(sizeof(queue));
    if (q == NULL) return NULL;

    q->head = NULL;
    q->tail = NULL;
    q->size = 0;
    InitializeCriticalSection(&q->lock);
    return q;
}
#elif __linux__ || defined(__unix__) || defined(__APPLE__)
queue *queue_new()
{
    queue *q = malloc(sizeof(queue));
    if (q == NULL) return NULL;

    q->head = NULL;
    q->tail = NULL;
    q->size = 0;
    pthread_rwlock_init(&q->lock, NULL);
    return q;
}
#endif

#if defined(_WIN32) || defined(_WIN64)
bool queue_enqueue(queue *q, void *data)
{
    queue_node *new_node = malloc(sizeof(queue_node));
    if (new_node == NULL) return false;

    new_node->data = data;
    new_node->next = NULL;

    EnterCriticalSection(&q->lock);
    if (q->tail == NULL)
    {
        q->head = new_node;
        q->tail = new_node;
    }
    else
    {
        q->tail->next = new_node;
        q->tail = new_node;
    }
    q->size++;
    LeaveCriticalSection(&q->lock);

    return true;
}
#elif __linux__ || defined(__unix__) || defined(__APPLE__)
bool queue_enqueue(queue *q, void *data)
{
    queue_node *new_node = malloc(sizeof(queue_node));
    if (new_node == NULL) return false;

    new_node->data = data;
    new_node->next = NULL;

    pthread_rwlock_wrlock(&q->lock);
    if (q->tail == NULL)
    {
        q->head = new_node;
        q->tail = new_node;
    }
    else
    {
        q->tail->next = new_node;
        q->tail = new_node;
    }
    q->size++;
    pthread_rwlock_unlock(&q->lock);

    return true;
}
#endif

#if defined(_WIN32) || defined(_WIN64)
void *queue_dequeue(queue *q)
{
    EnterCriticalSection(&q->lock);
    if (q->head == NULL)
    {
        LeaveCriticalSection(&q->lock);
        return NULL;
    }

    queue_node *node = q->head;
    void *data = node->data;
    q->head = q->head->next;

    if (q->head == NULL) q->tail = NULL;

    q->size--;
    LeaveCriticalSection(&q->lock);

    free(node);
    return data;
}
#elif __linux__ || defined(__unix__) || defined(__APPLE__)
void *queue_dequeue(queue *q)
{
    pthread_rwlock_wrlock(&q->lock);
    if (q->head == NULL)
    {
        pthread_rwlock_unlock(&q->lock);
        return NULL;
    }

    queue_node *node = q->head;
    void *data = node->data;
    q->head = q->head->next;

    if (q->head == NULL) q->tail = NULL;

    q->size--;
    pthread_rwlock_unlock(&q->lock);

    free(node);
    return data;
}
#endif

#if defined(_WIN32) || defined(_WIN64)
size_t queue_size(queue *q)
{
    EnterCriticalSection(&q->lock);
    size_t size = q->size;
    LeaveCriticalSection(&q->lock);
    return size;
}
#elif __linux__ || defined(__unix__) || defined(__APPLE__)
size_t queue_size(queue *q)
{
    pthread_rwlock_rdlock(&q->lock);
    size_t size = q->size;
    pthread_rwlock_unlock(&q->lock);
    return size;
}
#endif

void free_queue_node(queue_node *node)
{
    if (node == NULL) return;

    free(node);
    node = NULL;
}

#if defined(_WIN32) || defined(_WIN64)
void queue_destroy(queue *q)
{
    EnterCriticalSection(&q->lock);
    queue_node *current = q->head;

    while (current != NULL)
    {
        queue_node *next = current->next;
        free_queue_node(current);
        current = next;
    }

    LeaveCriticalSection(&q->lock);
    DeleteCriticalSection(&q->lock);
    free(q);
    q = NULL;
}
#elif __linux__ || defined(__unix__) || defined(__APPLE__)
void queue_destroy(queue *q)
{
    pthread_rwlock_wrlock(&q->lock);
    queue_node *current = q->head;

    while (current != NULL)
    {
        queue_node *next = current->next;
        free_queue_node(current);
        current = next;
    }

    pthread_rwlock_unlock(&q->lock);
    pthread_rwlock_destroy(&q->lock);
    free(q);
    q = NULL;
}
#endif