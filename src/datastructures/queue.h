/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __QUEUE_H__
#define __QUEUE_H__
#include "compat.h"

/* node pool configuration */
#define QUEUE_MAX_POOL_SIZE 64

/* spin count before blocking in dequeue_wait */
#define QUEUE_SPIN_COUNT 100

/**
 * queue_node_t
 * one node in the singly linked list backing the queue
 * @data pointer to user data
 * @next pointer to next node, published with release and consumed with acquire -- the only
 *       happens-before edge across the separate head_lock / tail_lock, so a node's payload stays
 *       visible to consumers
 */
typedef struct queue_node_t
{
    void *data;
    _Atomic(struct queue_node_t *) next;
} queue_node_t;

/**
 * queue_t
 * thread-safe FIFO queue with a dummy sentinel and separate head and tail locks so enqueue and
 * dequeue contend only through the payload publish, not each other
 * @head first node, protected by head_lock
 * @tail last node, protected by tail_lock
 * @dummy sentinel separating head and tail so the two locks stay independent
 * @size current element count, atomic so readers never take a lock
 * @shutdown non-zero once the queue is shut down, so blocked waiters release
 * @waiter_count threads currently blocked in queue_dequeue_wait
 * @head_lock guards dequeue and the head pointer
 * @tail_lock guards enqueue and the tail pointer
 * @read_lock rwlock coordinating read-only iterators against destructive ops -- peek, peek_at,
 *            foreach and snapshot take it shared, dequeue, dequeue_wait, clear and remove_if take
 *            it exclusive so iteration never races a removal
 * @not_empty condition signaled when the queue becomes non-empty or shuts down
 * @node_pool free list of reusable nodes that spares the allocator on churn
 * @pool_size current node-pool depth
 * @pool_lock guards the node pool
 * @max_pool_size the most nodes the pool retains before freeing to the heap
 */
typedef struct
{
    queue_node_t *head;
    queue_node_t *tail;
    queue_node_t *dummy;
    _Atomic(size_t) size;
    _Atomic(int) shutdown;
    _Atomic(int) waiter_count;
    pthread_mutex_t head_lock;
    pthread_mutex_t tail_lock;
    pthread_rwlock_t read_lock;
    pthread_cond_t not_empty;
    queue_node_t *node_pool;
    _Atomic(size_t) pool_size;
    pthread_mutex_t pool_lock;
    size_t max_pool_size;
} queue_t;

/**
 * queue_new
 * create a new queue
 * @return pointer to new queue, NULL on failure
 */
queue_t *queue_new(void);

/**
 * queue_enqueue
 * add an item to the back of the queue
 * @param queue the queue
 * @param data pointer to data to enqueue
 * @return 0 on success, -1 on failure
 */
int queue_enqueue(queue_t *queue, void *data);

/**
 * queue_dequeue
 * remove and return item from front of queue
 * @param queue the queue
 * @return pointer to dequeued data, NULL if queue is empty
 */
void *queue_dequeue(queue_t *queue);

/**
 * queue_dequeue_wait
 * remove and return item from front of queue, blocking until available
 * @param queue the queue
 * @return pointer to dequeued data, NULL if queue is destroyed or on error
 */
void *queue_dequeue_wait(queue_t *queue);

/**
 * queue_peek
 * view item at front of queue without removing it
 * @param queue the queue
 * @return pointer to front data, NULL if queue is empty
 */
void *queue_peek(queue_t *queue);

/**
 * queue_size
 * get current number of items in queue
 * @param queue the queue
 * @return number of items, 0 if queue is NULL or empty
 */
size_t queue_size(queue_t *queue);

/**
 * queue_is_empty
 * check if queue is empty
 * @param queue the queue
 * @return 1 if empty, 0 if not empty, -1 on error
 */
int queue_is_empty(queue_t *queue);

/**
 * queue_clear
 * remove all items from queue without freeing the data
 * @param queue the queue
 * @return 0 on success, -1 on error
 */
int queue_clear(queue_t *queue);

/**
 * queue_foreach
 * iterate over all items in the queue and call function for each
 * does not remove items from queue
 * @param queue the queue
 * @param fn callback function called for each item (receives data pointer and user context)
 * @param context user-provided context passed to callback function
 * @return number of items processed, -1 on error
 */
int queue_foreach(queue_t *queue, void (*fn)(void *data, void *context), void *context);

/**
 * queue_peek_at
 * peek at item at specific index without removing it
 * index 0 is head (oldest), index size-1 is tail (newest)
 * @param queue the queue
 * @param index the index to peek at
 * @return pointer to data at index, NULL if index out of bounds or error
 */
void *queue_peek_at(queue_t *queue, size_t index);

/**
 * queue_snapshot
 * copy all data pointers into a caller-provided array in a single O(n) traversal.
 * acquires read lock once, avoiding the O(n^2) cost of repeated queue_peek_at calls.
 * @param queue the queue
 * @param out array to fill (must have room for at least max_items elements)
 * @param max_items maximum number of items to copy
 * @return number of items actually copied
 */
size_t queue_snapshot(queue_t *queue, void **out, size_t max_items);

/**
 * queue_remove_if
 * remove every item where predicate(data, context) returns non-zero. acquires the same
 * wrlock + head_lock + tail_lock combination as queue_clear so dequeuers and enqueuers
 * are blocked for the duration. on_remove is invoked for each removed item before its
 * node is recycled, giving the caller a hook to decrement counters or free the data.
 * @param queue the queue
 * @param predicate returns non-zero for items to remove
 * @param context user-provided context passed to predicate and on_remove
 * @param on_remove optional callback invoked per removed item (NULL to skip)
 * @return number of items removed
 */
size_t queue_remove_if(queue_t *queue, int (*predicate)(void *data, void *context), void *context,
                       void (*on_remove)(void *data, void *context));

/**
 * queue_shutdown
 * signal shutdown to all waiting threads without freeing the queue
 * threads blocked in queue_dequeue_wait will return NULL
 * @param queue the queue to shutdown
 */
void queue_shutdown(queue_t *queue);

/**
 * queue_free
 * free the queue structure (does not free the data pointers)
 * @param queue the queue to free
 */
void queue_free(queue_t *queue);

/**
 * queue_free_with_data
 * free the queue and all data using provided free function
 * @param queue the queue to free
 * @param free_fn function to free each data element (can be NULL to skip)
 */
void queue_free_with_data(queue_t *queue, void (*free_fn)(void *));

#endif /* __QUEUE_H__ */