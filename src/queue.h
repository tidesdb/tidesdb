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
#ifndef QUEUE_H
#define QUEUE_H
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>

/*
 * queue_node
 * node for queue
 */
typedef struct queue_node {
    void *data;               // data in node
    struct queue_node *next;  // next node
} queue_node;

/*
 * queue
 * queue struct
 */
typedef struct queue {
    queue_node *head;       // head of queue
    queue_node *tail;       // tail of queue
    size_t size;            // size of queue
    pthread_rwlock_t lock;  // rw lock for queue
} queue;

/*
 * queue_new
 * creates new queue
 */
queue *queue_new();

/*
 * queue_enqueue
 * adds data to end of queue
 */
bool queue_enqueue(queue *q, void *data);

/*
 * queue_dequeue
 * removes data from front of queue
 */
void *queue_dequeue(queue *q);

/*
 * queue_size
 * returns size of queue
 */
size_t queue_size(queue *q);

/*
 * free_queue_node
 * frees queue node
 */
void free_queue_node(queue_node *node);

/*
 * queue_destroy
 * destroys queue
 */
void queue_destroy(queue *q);

#endif  // QUEUE_H