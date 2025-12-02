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
 * make_tagged_ptr
 * pack a pointer and counter into a single 64-bit value.
 * architecture-aware: handles both 32-bit and 64-bit pointers
 * @param ptr the node pointer
 * @param count the ABA counter
 * @return packed tagged pointer value
 */
static inline uint64_t make_tagged_ptr(queue_node_t *ptr, queue_counter_t count)
{
    return ((uint64_t)count << QUEUE_POINTER_BITS) |
           ((uint64_t)(uintptr_t)ptr & QUEUE_POINTER_MASK);
}

/**
 * get_ptr
 * extract the pointer from a tagged pointer value.
 * @param tagged the tagged pointer value
 * @return the node pointer
 */
static inline queue_node_t *get_ptr(uint64_t tagged)
{
    return (queue_node_t *)(uintptr_t)(tagged & QUEUE_POINTER_MASK);
}

/**
 * get_count
 * extract the counter from a tagged pointer value.
 * architecture-aware: returns appropriate counter size
 * @param tagged the tagged pointer value
 * @return the ABA counter
 */
static inline queue_counter_t get_count(uint64_t tagged)
{
    return (queue_counter_t)(tagged >> QUEUE_POINTER_BITS);
}

/**
 * queue_alloc_node
 * allocate a new queue node.
 * @return the allocated node, or NULL on failure
 */
static inline queue_node_t *queue_alloc_node(void)
{
    queue_node_t *node = (queue_node_t *)malloc(sizeof(queue_node_t));
    if (node)
    {
        node->data = NULL;
        atomic_store_explicit(&node->next, 0, memory_order_relaxed);
    }
    return node;
}

/**
 * queue_free_node
 * free a queue node.
 * @param node the node to free
 */
static inline void queue_free_node(queue_node_t *node)
{
    if (node) free(node);
}

/* forward declaration */
static void queue_reclaim_retired(queue_t *queue);

/**
 * queue_retire_node
 * add a node to the retire list for deferred reclamation.
 * nodes are not freed immediately to prevent use-after-free.
 * @param queue the queue
 * @param node the node to retire
 */
static void queue_retire_node(queue_t *queue, queue_node_t *node)
{
    if (queue == NULL || node == NULL) return;

    queue_retired_node_t *retired = (queue_retired_node_t *)malloc(sizeof(queue_retired_node_t));
    if (retired == NULL)
    {
        /* fallback: free immediately if we can't allocate retire node */
        queue_free_node(node);
        return;
    }

    retired->node = node;

    pthread_mutex_lock(&queue->retire_lock);
    retired->next = queue->retire_list;
    queue->retire_list = retired;
    size_t count = atomic_fetch_add_explicit(&queue->retire_count, 1, memory_order_relaxed) + 1;
    pthread_mutex_unlock(&queue->retire_lock);

    /* reclaim aggressively to prevent unbounded growth in long-lived queues
     * threshold of QUEUE_RETIRE_THRESHOLD provides grace period while keeping memory bounded */
    if (count > QUEUE_RETIRE_THRESHOLD)
    {
        queue_reclaim_retired(queue);
    }
}

/**
 * queue_reclaim_retired
 * free all nodes in the retire list.
 * called periodically to reclaim memory after a grace period.
 * @param queue the queue
 */
static void queue_reclaim_retired(queue_t *queue)
{
    if (queue == NULL) return;

    pthread_mutex_lock(&queue->retire_lock);
    queue_retired_node_t *current = queue->retire_list;
    queue->retire_list = NULL;
    atomic_store_explicit(&queue->retire_count, 0, memory_order_relaxed);
    pthread_mutex_unlock(&queue->retire_lock);

    /* free all retired nodes outside the lock */
    while (current != NULL)
    {
        queue_retired_node_t *next = current->next;
        queue_free_node(current->node);
        free(current);
        current = next;
    }
}

/**
 * backoff
 * perform exponential backoff to reduce contention.
 * @param count pointer to current backoff count (will be updated)
 */
static inline void backoff(int *count)
{
    int limit = *count;
    for (int i = 0; i < limit; i++)
    {
        cpu_pause();
    }
    /* exponential backoff with cap */
    if (*count < QUEUE_MAX_BACKOFF)
    {
        *count *= 2;
    }
}

queue_t *queue_new(void)
{
    queue_t *queue = (queue_t *)malloc(sizeof(queue_t));
    if (queue == NULL) return NULL;

    /* allocate the dummy node as per Michael-Scott algorithm */
    queue_node_t *dummy = queue_alloc_node();
    if (dummy == NULL)
    {
        free(queue);
        return NULL;
    }

    dummy->data = NULL;
    atomic_store_explicit(&dummy->next, make_tagged_ptr(NULL, 0), memory_order_relaxed);

    /* both head and tail point to the dummy node initially */
    atomic_store_explicit(&queue->head, make_tagged_ptr(dummy, 0), memory_order_relaxed);
    atomic_store_explicit(&queue->tail, make_tagged_ptr(dummy, 0), memory_order_relaxed);
    atomic_store_explicit(&queue->size, 0, memory_order_relaxed);
    atomic_store_explicit(&queue->shutdown, 0, memory_order_relaxed);

    /* initialize retire list for deferred reclamation */
    queue->retire_list = NULL;
    atomic_store_explicit(&queue->retire_count, 0, memory_order_relaxed);
    if (pthread_mutex_init(&queue->retire_lock, NULL) != 0)
    {
        free(dummy);
        free(queue);
        return NULL;
    }

    return queue;
}

int queue_enqueue(queue_t *queue, void *data)
{
    if (queue == NULL) return -1;

    queue_node_t *node = queue_alloc_node();
    if (node == NULL) return -1;

    node->data = data;

    atomic_store_explicit(&node->next, make_tagged_ptr(NULL, 0), memory_order_relaxed);

    int backoff_count = QUEUE_INITIAL_BACKOFF;

    while (1)
    {
        uint64_t tail = atomic_load_explicit(&queue->tail, memory_order_acquire);
        queue_node_t *tail_ptr = get_ptr(tail);
        queue_counter_t tail_count = get_count(tail);

        uint64_t next = atomic_load_explicit(&tail_ptr->next, memory_order_acquire);
        queue_node_t *next_ptr = get_ptr(next);
        queue_counter_t next_count = get_count(next);

        uint64_t tail_check = atomic_load_explicit(&queue->tail, memory_order_acquire);
        if (tail == tail_check)
        {
            if (next_ptr == NULL)
            {
                uint64_t new_next = make_tagged_ptr(node, next_count + 1);
                if (atomic_compare_exchange_weak_explicit(&tail_ptr->next, &next, new_next,
                                                          memory_order_release,
                                                          memory_order_relaxed))
                {
                    uint64_t new_tail = make_tagged_ptr(node, tail_count + 1);
                    atomic_compare_exchange_strong_explicit(
                        &queue->tail, &tail, new_tail, memory_order_release, memory_order_relaxed);
                    break;
                }
            }
            else
            {
                uint64_t new_tail = make_tagged_ptr(next_ptr, tail_count + 1);
                atomic_compare_exchange_strong_explicit(&queue->tail, &tail, new_tail,
                                                        memory_order_release, memory_order_relaxed);
            }
        }

        backoff(&backoff_count);
    }

    atomic_fetch_add_explicit(&queue->size, 1, memory_order_relaxed);

    return 0;
}

void *queue_dequeue(queue_t *queue)
{
    if (queue == NULL) return NULL;

    int backoff_count = QUEUE_INITIAL_BACKOFF;
    void *data = NULL;
    queue_node_t *old_head_ptr = NULL;

    while (1)
    {
        uint64_t head = atomic_load_explicit(&queue->head, memory_order_acquire);
        queue_node_t *head_ptr = get_ptr(head);
        queue_counter_t head_count = get_count(head);

        uint64_t tail = atomic_load_explicit(&queue->tail, memory_order_acquire);
        queue_node_t *tail_ptr = get_ptr(tail);
        queue_counter_t tail_count = get_count(tail);

        /* verify head hasn't changed before dereferencing head_ptr
         * this prevents use-after-free if another thread dequeued and freed the node */
        uint64_t head_check = atomic_load_explicit(&queue->head, memory_order_acquire);
        if (head != head_check)
        {
            backoff(&backoff_count);
            continue;
        }

        /* now safe to read head_ptr->next since we verified head is still valid */
        uint64_t next = atomic_load_explicit(&head_ptr->next, memory_order_acquire);
        queue_node_t *next_ptr = get_ptr(next);

        /* check again after reading next to ensure consistency */
        head_check = atomic_load_explicit(&queue->head, memory_order_acquire);
        if (head == head_check)
        {
            if (head_ptr == tail_ptr)
            {
                if (next_ptr == NULL)
                {
                    return NULL;
                }

                uint64_t new_tail = make_tagged_ptr(next_ptr, tail_count + 1);
                atomic_compare_exchange_strong_explicit(&queue->tail, &tail, new_tail,
                                                        memory_order_release, memory_order_relaxed);
            }
            else
            {
                data = next_ptr->data;

                uint64_t new_head = make_tagged_ptr(next_ptr, head_count + 1);
                if (atomic_compare_exchange_weak_explicit(
                        &queue->head, &head, new_head, memory_order_release, memory_order_relaxed))
                {
                    old_head_ptr = head_ptr;
                    break;
                }
            }
        }

        backoff(&backoff_count);
    }

    if (old_head_ptr != NULL)
    {
        /* defer freeing to prevent use-after-free in concurrent operations */
        queue_retire_node(queue, old_head_ptr);
    }

    atomic_fetch_sub_explicit(&queue->size, 1, memory_order_relaxed);

    return data;
}

void *queue_dequeue_wait(queue_t *queue)
{
    if (queue == NULL) return NULL;

    int backoff_count = QUEUE_INITIAL_BACKOFF;
    int spin_count = 0;
    const int MAX_SPINS_BEFORE_YIELD = 1000;

    while (!atomic_load_explicit(&queue->shutdown, memory_order_acquire))
    {
        void *data = queue_dequeue(queue);
        if (data != NULL)
        {
            return data;
        }

        spin_count++;
        if (spin_count < MAX_SPINS_BEFORE_YIELD)
        {
            backoff(&backoff_count);
        }
        else
        {
            cpu_yield();
            spin_count = 0;
            backoff_count = QUEUE_INITIAL_BACKOFF;
        }
    }

    return queue_dequeue(queue);
}

void *queue_peek(queue_t *queue)
{
    if (queue == NULL) return NULL;

    uint64_t head = atomic_load_explicit(&queue->head, memory_order_acquire);
    queue_node_t *head_ptr = get_ptr(head);

    uint64_t next = atomic_load_explicit(&head_ptr->next, memory_order_acquire);
    queue_node_t *next_ptr = get_ptr(next);

    if (next_ptr == NULL)
    {
        return NULL;
    }

    return next_ptr->data;
}

size_t queue_size(queue_t *queue)
{
    if (queue == NULL) return 0;

    return atomic_load_explicit(&queue->size, memory_order_relaxed);
}

int queue_is_empty(queue_t *queue)
{
    if (queue == NULL) return -1;

    uint64_t head = atomic_load_explicit(&queue->head, memory_order_acquire);
    queue_node_t *head_ptr = get_ptr(head);

    uint64_t next = atomic_load_explicit(&head_ptr->next, memory_order_acquire);
    queue_node_t *next_ptr = get_ptr(next);

    return (next_ptr == NULL) ? 1 : 0;
}

int queue_clear(queue_t *queue)
{
    if (queue == NULL) return -1;

    while (queue_dequeue(queue) != NULL)
    {
        /* cont until empty */
    }

    return 0;
}

int queue_foreach(queue_t *queue, void (*fn)(void *data, void *context), void *context)
{
    if (queue == NULL || fn == NULL) return -1;

    int count = 0;

    uint64_t head = atomic_load_explicit(&queue->head, memory_order_acquire);
    queue_node_t *current = get_ptr(head);

    /* move to first real node */
    uint64_t next = atomic_load_explicit(&current->next, memory_order_acquire);
    current = get_ptr(next);

    while (current != NULL)
    {
        fn(current->data, context);
        count++;

        next = atomic_load_explicit(&current->next, memory_order_acquire);
        current = get_ptr(next);
    }

    return count;
}

void *queue_peek_at(queue_t *queue, size_t index)
{
    if (queue == NULL) return NULL;

    size_t size = atomic_load_explicit(&queue->size, memory_order_relaxed);
    if (index >= size)
    {
        return NULL;
    }

    uint64_t head = atomic_load_explicit(&queue->head, memory_order_acquire);
    queue_node_t *current = get_ptr(head);

    uint64_t next = atomic_load_explicit(&current->next, memory_order_acquire);
    current = get_ptr(next);

    for (size_t i = 0; i < index && current != NULL; i++)
    {
        next = atomic_load_explicit(&current->next, memory_order_acquire);
        current = get_ptr(next);
    }

    return current ? current->data : NULL;
}

void queue_free(queue_t *queue)
{
    if (queue == NULL) return;

    atomic_store_explicit(&queue->shutdown, 1, memory_order_release);

    cpu_yield();

    /* reclaim all retired nodes before freeing queue */
    queue_reclaim_retired(queue);

    uint64_t head = atomic_load_explicit(&queue->head, memory_order_acquire);
    queue_node_t *current = get_ptr(head);

    while (current != NULL)
    {
        uint64_t next = atomic_load_explicit(&current->next, memory_order_relaxed);
        queue_node_t *next_ptr = get_ptr(next);
        queue_free_node(current);
        current = next_ptr;
    }

    pthread_mutex_destroy(&queue->retire_lock);
    free(queue);
}

void queue_free_with_data(queue_t *queue, void (*free_fn)(void *))
{
    if (queue == NULL) return;

    atomic_store_explicit(&queue->shutdown, 1, memory_order_release);

    cpu_yield();

    /* reclaim all retired nodes before freeing queue */
    queue_reclaim_retired(queue);

    uint64_t head = atomic_load_explicit(&queue->head, memory_order_acquire);
    queue_node_t *current = get_ptr(head);

    uint64_t next = atomic_load_explicit(&current->next, memory_order_relaxed);
    queue_node_t *next_ptr = get_ptr(next);
    queue_free_node(current);
    current = next_ptr;

    while (current != NULL)
    {
        next = atomic_load_explicit(&current->next, memory_order_relaxed);
        next_ptr = get_ptr(next);

        if (free_fn != NULL && current->data != NULL)
        {
            free_fn(current->data);
        }
        queue_free_node(current);
        current = next_ptr;
    }

    pthread_mutex_destroy(&queue->retire_lock);
    free(queue);
}