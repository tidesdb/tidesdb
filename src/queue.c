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
    /* allocate memory for the queue */
    queue *q = malloc(sizeof(queue));
    if (q == NULL) return NULL; /* check if successful */

    q->head = NULL;
    q->tail = NULL;
    q->size = 0;
    InitializeCriticalSection(&q->lock); /* initialize the lock */
    return q;
}
#elif __linux__ || defined(__unix__) || defined(__APPLE__)
queue_t *queue_new()
{
    /* allocate memory for the queue */
    queue_t *q = malloc(sizeof(queue_t));
    if (q == NULL) return NULL; /* check if successful */

    /* initialize the queue */
    q->head = NULL;
    q->tail = NULL;
    q->size = 0;
    pthread_rwlock_init(&q->lock, NULL); /* initialize the lock */
    return q;
}
#endif

#if defined(_WIN32) || defined(_WIN64)
bool queue_enqueue(queue_t *q, void *data)
{
    /* allocate memory for the new node */
    queue_node_t *new_node = malloc(sizeof(queue_node_t));
    if (new_node == NULL) return false;

    new_node->data = data;
    new_node->next = NULL;

    /* lock the queue */
    EnterCriticalSection(&q->lock);
    if (q->tail == NULL)
    {
        q->head = new_node; /* set the head */
        q->tail = new_node; /* set the tail */
    }
    else
    {
        q->tail->next = new_node;
        q->tail = new_node;
    }
    q->size++;                      /* increment the size */
    LeaveCriticalSection(&q->lock); /* unlock the queue */

    return true;
}
#elif __linux__ || defined(__unix__) || defined(__APPLE__)
int queue_enqueue(queue_t *q, void *data)
{
    queue_node_t *new_node = malloc(sizeof(queue_node_t)); /* allocate memory for the new node */
    if (new_node == NULL) return -1;                       /* check if successful */

    new_node->data = data; /* set the data */
    new_node->next = NULL; /* set the next node to NULL */

    /* lock the queue */
    pthread_rwlock_wrlock(&q->lock);
    if (q->tail == NULL) /* check if the queue is empty */
    {
        q->head = new_node;
        q->tail = new_node;
    }
    else
    {
        q->tail->next = new_node; /* set the next node */
        q->tail = new_node;       /* set the tail */
    }
    q->size++;                       /* increment the size */
    pthread_rwlock_unlock(&q->lock); /* unlock the queue */

    return 0;
}
#endif

#if defined(_WIN32) || defined(_WIN64)
void *queue_dequeue(queue_t *q)
{
    EnterCriticalSection(&q->lock); /* lock the queue */
    if (q->head == NULL)
    {
        LeaveCriticalSection(&q->lock); /* unlock the queue */
        return NULL;
    }

    queue_node_t *node = q->head; /* dequeue a node */
    void *data = node->data;
    q->head = q->head->next;

    if (q->head == NULL) q->tail = NULL; /* check if the queue is empty */

    q->size--;                      /* decrement the size */
    LeaveCriticalSection(&q->lock); /* unlock the queue */

    free(node); /* free the memory allocated for the node */
    return data;
}
#elif __linux__ || defined(__unix__) || defined(__APPLE__)
void *queue_dequeue(queue_t *q)
{
    pthread_rwlock_wrlock(&q->lock); /* lock the queue */
    if (q->head == NULL)             /* check if the queue is empty */
    {
        pthread_rwlock_unlock(&q->lock); /* unlock the queue */
        return NULL;
    }

    /* dequeue a node */
    queue_node_t *node = q->head;
    void *data = node->data;
    q->head = q->head->next;

    /* check if the queue is empty */
    if (q->head == NULL) q->tail = NULL;

    /* decrement the size */
    q->size--;

    /* unlock the queue */
    pthread_rwlock_unlock(&q->lock);

    free(node); /* free the memory allocated for the node */
    return data;
}
#endif

#if defined(_WIN32) || defined(_WIN64)
size_t queue_size(queue_t *q)
{
    EnterCriticalSection(&q->lock); /* lock the queue */
    size_t size = q->size;          /* get the size */
    LeaveCriticalSection(&q->lock); /* unlock the queue */
    return size;
}
#elif __linux__ || defined(__unix__) || defined(__APPLE__)
size_t queue_size(queue_t *q)
{
    pthread_rwlock_rdlock(&q->lock); /* lock the queue */
    size_t size = q->size;           /* get the size */
    pthread_rwlock_unlock(&q->lock); /* unlock the queue */
    return size;
}
#endif

void free_queue_node(queue_node_t *node)
{
    if (node == NULL) return; /* check if the node is NULL */

    free(node);  /* free the memory allocated for the node */
    node = NULL; /* set the node to NULL */
}

#if defined(_WIN32) || defined(_WIN64)
void queue_destroy(queue_t *q)
{
    /* lock the queue */
    EnterCriticalSection(&q->lock);

    queue_node *current = q->head; /* we start at the head */

    while (current != NULL)
    {
        queue_node_t *next = current->next;
        free_queue_node(current);
        current = next; /* move to the next node */
    }

    LeaveCriticalSection(&q->lock);  /* unlock the queue */
    DeleteCriticalSection(&q->lock); /* destroy the lock */
    free(q);                         /* free the memory allocated for the queue */
    q = NULL;                        /* set the queue to NULL */
}
#elif __linux__ || defined(__unix__) || defined(__APPLE__)
void queue_destroy(queue_t *q)
{
    /* lock the queue */
    pthread_rwlock_wrlock(&q->lock);

    /* free all the nodes in the queue */
    queue_node_t *current = q->head;

    while (current != NULL)
    {
        queue_node_t *next = current->next;
        free_queue_node(current);
        current = next; /* move to the next node */
    }

    pthread_rwlock_unlock(&q->lock);  /* unlock the queue */
    pthread_rwlock_destroy(&q->lock); /* destroy the lock */
    free(q);                          /* free the memory allocated for the queue */
    q = NULL;                         /* set the queue to NULL */
}
#endif