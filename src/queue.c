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

size_t queue_size(queue *q)
{
    pthread_rwlock_rdlock(&q->lock);
    size_t size = q->size;
    pthread_rwlock_unlock(&q->lock);
    return size;
}

void free_queue_node(queue_node *node)
{
    if (node == NULL) return;

    free(node);
    node = NULL;
}

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