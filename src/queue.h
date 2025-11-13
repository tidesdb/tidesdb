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
#ifndef __QUEUE_H__
#define __QUEUE_H__
#include "compat.h"

/*
 * queue_node_t
 * internal node structure for the queue
 * @param data pointer to user data
 * @param next pointer to next node
 */
typedef struct queue_node_t
{
    void *data;
    struct queue_node_t *next;
} queue_node_t;

/*
 * queue_t
 * thread-safe FIFO queue implementation with node pooling
 * @param head pointer to first node
 * @param tail pointer to last node
 * @param size current number of elements (atomic for lock-free reads)
 * @param shutdown has queue been shutdown?
 * @param waiter_count number of threads currently waiting in queue_dequeue_wait
 * @param lock mutex for thread safety
 * @param not_empty condition variable signaled when queue becomes non-empty
 * @param node_pool free list of reusable nodes for performance
 * @param pool_size current size of node pool
 * @param max_pool_size maximum nodes to keep in pool
 */
typedef struct
{
    queue_node_t *head;
    queue_node_t *tail;
    _Atomic(size_t) size;
    int shutdown;
    int waiter_count;
    pthread_mutex_t lock;
    pthread_cond_t not_empty;
    queue_node_t *node_pool;
    size_t pool_size;
    size_t max_pool_size;
} queue_t;

/*
 * queue_new
 * create a new queue
 * @return pointer to new queue, NULL on failure
 */
queue_t *queue_new(void);

/*
 * queue_enqueue
 * add an item to the back of the queue
 * @param queue the queue
 * @param data pointer to data to enqueue
 * @return 0 on success, -1 on failure
 */
int queue_enqueue(queue_t *queue, void *data);

/*
 * queue_dequeue
 * remove and return item from front of queue
 * @param queue the queue
 * @return pointer to dequeued data, NULL if queue is empty
 */
void *queue_dequeue(queue_t *queue);

/*
 * queue_dequeue_wait
 * remove and return item from front of queue, blocking until available
 * @param queue the queue
 * @return pointer to dequeued data, NULL if queue is destroyed or on error
 */
void *queue_dequeue_wait(queue_t *queue);

/*
 * queue_peek
 * view item at front of queue without removing it
 * @param queue the queue
 * @return pointer to front data, NULL if queue is empty
 */
void *queue_peek(queue_t *queue);

/*
 * queue_size
 * get current number of items in queue
 * @param queue the queue
 * @return number of items, 0 if queue is NULL or empty
 */
size_t queue_size(queue_t *queue);

/*
 * queue_is_empty
 * check if queue is empty
 * @param queue the queue
 * @return 1 if empty, 0 if not empty, -1 on error
 */
int queue_is_empty(queue_t *queue);

/*
 * queue_clear
 * remove all items from queue without freeing the data
 * @param queue the queue
 * @return 0 on success, -1 on error
 */
int queue_clear(queue_t *queue);

/*
 * queue_foreach
 * iterate over all items in the queue and call function for each
 * does not remove items from queue
 * @param queue the queue
 * @param fn callback function called for each item (receives data pointer and user context)
 * @param context user-provided context passed to callback function
 * @return number of items processed, -1 on error
 */
int queue_foreach(queue_t *queue, void (*fn)(void *data, void *context), void *context);

/*
 * queue_peek_at
 * peek at item at specific index without removing it
 * index 0 is head (oldest), index size-1 is tail (newest)
 * @param queue the queue
 * @param index the index to peek at
 * @return pointer to data at index, NULL if index out of bounds or error
 */
void *queue_peek_at(queue_t *queue, size_t index);

/*
 * queue_free
 * free the queue structure (does not free the data pointers)
 * @param queue the queue to free
 */
void queue_free(queue_t *queue);

/*
 * queue_free_with_data
 * free the queue and all data using provided free function
 * @param queue the queue to free
 * @param free_fn function to free each data element (can be NULL to skip)
 */
void queue_free_with_data(queue_t *queue, void (*free_fn)(void *));

#endif /* __QUEUE_H__ */
