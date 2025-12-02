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

/* maximum backoff iterations for spinning */
#define QUEUE_MAX_BACKOFF 1024

#define QUEUE_INITIAL_BACKOFF 4

#define QUEUE_RETIRE_THRESHOLD 10

/**
 * QUEUE_POINTER_BITS
 * number of bits used for the pointer in the tagged pointer.
 * architecture-specific:
 * - 64-bit: 48 bits for pointer, 16 bits for counter
 * - 32-bit: 32 bits for pointer, 32 bits for counter
 * both fit in a 64-bit atomic value for ops
 */
#if UINTPTR_MAX == 0xFFFFFFFFFFFFFFFFULL
/* 64-bit architecture */
#define QUEUE_POINTER_BITS 48
#define QUEUE_COUNTER_BITS 16
#else
/* 32-bit architecture */
#define QUEUE_POINTER_BITS 32
#define QUEUE_COUNTER_BITS 32
#endif

#define QUEUE_POINTER_MASK ((1ULL << QUEUE_POINTER_BITS) - 1)
#define QUEUE_COUNTER_MASK ((1ULL << QUEUE_COUNTER_BITS) - 1)

/* architecture-aware counter type */
#if UINTPTR_MAX == 0xFFFFFFFFFFFFFFFFULL
typedef uint16_t queue_counter_t; /* 64-bit arch: 16-bit counter */
#else
typedef uint32_t queue_counter_t; /* 32-bit arch: 32-bit counter */
#endif

/**
 * queue_node_t
 * internal node structure for the queue.
 * @param data pointer to user data
 * @param next tagged pointer to next node (includes ABA counter)
 */
typedef struct queue_node_t
{
    void *data;
    _Atomic(uint64_t) next;
} queue_node_t;

/**
 * queue_tagged_ptr_t
 * helper structure for working with tagged pointers.
 * used to pack a pointer and counter together for atomic CAS operations.
 * counter size is architecture-specific (16-bit on 64-bit, 32-bit on 32-bit)
 */
typedef struct
{
    queue_node_t *ptr;
    queue_counter_t count;
} queue_tagged_ptr_t;

/**
 * queue_retired_node_t
 * node in the retire list for deferred reclamation
 * @param node the retired node to be freed later
 * @param next next retired node in the list
 */
typedef struct queue_retired_node_t
{
    queue_node_t *node;
    struct queue_retired_node_t *next;
} queue_retired_node_t;

/**
 * queue_t
 * FIFO queue implementation
 * @param head tagged pointer to dummy node (dequeue end)
 * @param tail tagged pointer to last node (enqueue end)
 * @param size current number of elements (approximate, for monitoring only)
 * @param shutdown flag to signal queue shutdown for waiting operations
 * @param retire_list list of nodes waiting to be freed (deferred reclamation)
 * @param retire_lock mutex protecting the retire list
 * @param retire_count number of nodes in retire list
 */
typedef struct
{
    ATOMIC_ALIGN(16) _Atomic(uint64_t) head;
    ATOMIC_ALIGN(16) _Atomic(uint64_t) tail;
    _Atomic(size_t) size;
    _Atomic(int) shutdown;
    queue_retired_node_t *retire_list;
    pthread_mutex_t retire_lock;
    _Atomic(size_t) retire_count;
} queue_t;

/**
 * queue_new
 * create a new queue.
 * allocates a dummy node
 * @return pointer to new queue, NULL on failure
 */
queue_t *queue_new(void);

/**
 * queue_enqueue
 * add an item to the back of the queue.
 * uses CAS to atomically link the new node and update the tail pointer.
 * @param queue the queue
 * @param data pointer to data to enqueue
 * @return 0 on success, -1 on failure
 */
int queue_enqueue(queue_t *queue, void *data);

/**
 * queue_dequeue
 * remove and return item from front of queue.
 * uses CAS to atomically swing the head pointer to the next node.
 * @param queue the queue
 * @return pointer to dequeued data, NULL if queue is empty
 */
void *queue_dequeue(queue_t *queue);

/**
 * queue_dequeue_wait
 * remove and return item from front of queue, spinning until available.
 * uses exponential backoff to reduce contention while waiting.
 * @param queue the queue
 * @return pointer to dequeued data, NULL if queue is shutdown
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
 * get approximate number of items in queue
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
 * remove all items from queue without freeing the data.
 * should only be called when exclusive access is guaranteed.
 * @param queue the queue
 * @return 0 on success, -1 on error
 */
int queue_clear(queue_t *queue);

/**
 * queue_foreach
 * iterate over all items in the queue and call function for each.
 * should only be called when exclusive access is guaranteed.
 * @param queue the queue
 * @param fn callback function called for each item
 * @param context user-provided context passed to callback
 * @return number of items processed, -1 on error
 */
int queue_foreach(queue_t *queue, void (*fn)(void *data, void *context), void *context);

/**
 * queue_peek_at
 * peek at item at specific index without removing it.
 * index 0 is head (oldest), index size-1 is tail (newest).
 * @param queue the queue
 * @param index the index to peek at
 * @return pointer to data at index, NULL if index out of bounds or error
 */
void *queue_peek_at(queue_t *queue, size_t index);

/**
 * queue_free
 * free the queue structure (does not free the data pointers).
 * sets shutdown flag and waits briefly for operations to complete.
 * @param queue the queue to free
 */
void queue_free(queue_t *queue);

/**
 * queue_free_with_data
 * free the queue and all data using provided free function.
 * @param queue the queue to free
 * @param free_fn function to free each data element (can be NULL to skip)
 */
void queue_free_with_data(queue_t *queue, void (*free_fn)(void *));

#endif /* __QUEUE_H__ */