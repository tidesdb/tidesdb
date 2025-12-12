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
#ifndef __QUEUE_H__
#define __QUEUE_H__
#include "compat.h"

/**
 * QUEUE_TAG_BITS
 * number of bits used for the ABA counter in tagged pointers.
 * on 64-bit systems, we use the upper bits for the tag.
 */
#if UINTPTR_MAX == 0xFFFFFFFFFFFFFFFF
#define QUEUE_TAG_BITS 16
#define QUEUE_TAG_MASK ((uintptr_t)0xFFFF000000000000ULL)
#define QUEUE_PTR_MASK ((uintptr_t)0x0000FFFFFFFFFFFFULL)
#else
/* 32-bit systems we use upper 8 bits for tag */
#define QUEUE_TAG_BITS 8
#define QUEUE_TAG_MASK ((uintptr_t)0xFF000000UL)
#define QUEUE_PTR_MASK ((uintptr_t)0x00FFFFFFUL)
#endif

/* max spin iterations before yielding */
#define MAX_SPIN_COUNT 100

/**
 * tagged_ptr_t
 * tagged pointer to solve the ABA problem in lock-free algorithms.
 * combines a pointer with a version counter.
 */
typedef struct
{
    uintptr_t value;
} tagged_ptr_t;

/**
 * queue_node_t
 * internal node structure for the lock-free queue.
 * @param data pointer to user data
 * @param next tagged pointer to next node (includes ABA counter)
 */
typedef struct queue_node_t
{
    void *data;
    _Atomic(tagged_ptr_t) next;
} queue_node_t;

/**
 * queue_t
 * lock-free FIFO queue implementation.
 * @param head tagged pointer to sentinel/first node (atomic)
 * @param tail tagged pointer to last node (atomic)
 * @param size current number of elements (atomic, approximate)
 * @param shutdown has queue been shutdown?
 * @param waiter_count number of threads currently waiting
 * @param wait_lock mutex for blocking wait operations
 * @param not_empty condition variable for blocking waits
 */
typedef struct
{
    _Atomic(tagged_ptr_t) head;
    _Atomic(tagged_ptr_t) tail;
    _Atomic(size_t) size;
    _Atomic(int) shutdown;
    _Atomic(int) waiter_count;
    pthread_mutex_t wait_lock;
    pthread_cond_t not_empty;
} queue_t;

/**
 * queue_new
 * create a new lock-free queue.
 * init with a sentinel node.
 * @return pointer to new queue, NULL on failure
 */
queue_t *queue_new(void);

/**
 * queue_enqueue
 * add an item to the back of the queue (lock-free).
 * uses CAS operations for thread safety.
 * @param queue the queue
 * @param data pointer to data to enqueue
 * @return 0 on success, -1 on failure
 */
int queue_enqueue(queue_t *queue, void *data);

/**
 * queue_dequeue
 * remove and return item from front of queue (lock-free).
 * uses CAS operations for thread safety.
 * @param queue the queue
 * @return pointer to dequeued data, NULL if queue is empty
 */
void *queue_dequeue(queue_t *queue);

/**
 * queue_dequeue_wait
 * remove and return item from front of queue, blocking until available.
 * uses condition variable for efficient waiting.
 * @param queue the queue
 * @return pointer to dequeued data, NULL if queue is destroyed or on error
 */
void *queue_dequeue_wait(queue_t *queue);

/**
 * queue_peek
 * view item at front of queue without removing it.
 * inn a lock-free queue, the peeked value may be dequeued
 * by another thread before caller can act on it.
 * @param queue the queue
 * @return pointer to front data, NULL if queue is empty
 */
void *queue_peek(queue_t *queue);

/**
 * queue_size
 * get approximate number of items in queue.
 * in a concurrent environment, this is approximate.
 * @param queue the queue
 * @return number of items, 0 if queue is NULL or empty
 */
size_t queue_size(queue_t *queue);

/**
 * queue_is_empty
 * check if queue is empty.
 * result may be stale in concurrent environment.
 * @param queue the queue
 * @return 1 if empty, 0 if not empty, -1 on error
 */
int queue_is_empty(queue_t *queue);

/**
 * queue_clear
 * remove all items from queue without freeing the data.
 * not lock-free, acquires wait_lock.
 * @param queue the queue
 * @return 0 on success, -1 on error
 */
int queue_clear(queue_t *queue);

/**
 * queue_foreach
 * iterate over all items in the queue and call function for each.
 * not lock-free, provides snapshot iteration.
 * items may be added/removed during iteration.
 * @param queue the queue
 * @param fn callback function called for each item
 * @param context user-provided context passed to callback
 * @return number of items processed, -1 on error
 */
int queue_foreach(queue_t *queue, void (*fn)(void *data, void *context), void *context);

/**
 * queue_peek_at
 * peek at item at specific index without removing it.
 * not lock-free, index may be invalid by the time caller acts.
 * @param queue the queue
 * @param index the index to peek at (0 = head)
 * @return pointer to data at index, NULL if index out of bounds
 */
void *queue_peek_at(queue_t *queue, size_t index);

/**
 * queue_snapshot_with_refs
 * create a safe snapshot of queue items with reference counting.
 * takes references on all items atomically to prevent use-after-free.
 * caller must release references using the provided unref callback.
 * @param queue the queue
 * @param items output array of items (caller must free)
 * @param count output number of items
 * @param ref_fn callback to increment reference count (called for each item)
 * @return 0 on success, -1 on failure
 */
int queue_snapshot_with_refs(queue_t *queue, void ***items, size_t *count,
                             void (*ref_fn)(void *item));

/**
 * queue_free
 * free the queue structure (does not free the data pointers).
 * wakes all waiting threads before destruction.
 * @param queue the queue to free
 */
void queue_free(queue_t *queue);

/**
 * queue_free_with_data
 * free the queue and all data using provided free function.
 * @param queue the queue to free
 * @param free_fn function to free each data element (can be NULL)
 */
void queue_free_with_data(queue_t *queue, void (*free_fn)(void *));

#endif /* __QUEUE_H__ */