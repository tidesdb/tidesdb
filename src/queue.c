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

#include <sched.h>

/**
 * Michael-Scott Lock-Free Queue Implementation
 *
 * Reference:
 * M. M. Michael and M. L. Scott, "Simple, Fast, and Practical Non-Blocking
 * and Blocking Concurrent Queue Algorithms," PODC 1996.
 *
 * This implementation uses tagged pointers to solve the ABA problem.
 * The queue always maintains a sentinel (dummy) node at the head.
 */

/* Maximum spin iterations before yielding */
#define MAX_SPIN_COUNT 100

/* --------------------------------------------------------------------------
 * Tagged Pointer Helpers
 * -------------------------------------------------------------------------- */

/**
 * make_tagged_ptr
 * Create a tagged pointer combining a raw pointer and version tag.
 * @param ptr the raw pointer
 * @param tag the version counter
 * @return tagged pointer value
 */
static inline tagged_ptr_t make_tagged_ptr(queue_node_t *ptr, uintptr_t tag)
{
    tagged_ptr_t tp;
    tp.value = ((uintptr_t)ptr & QUEUE_PTR_MASK) |
               ((tag << (sizeof(uintptr_t) * 8 - QUEUE_TAG_BITS)) & QUEUE_TAG_MASK);
    return tp;
}

/**
 * get_ptr
 * Extract the raw pointer from a tagged pointer.
 * @param tp the tagged pointer
 * @return raw pointer to queue_node_t
 */
static inline queue_node_t *get_ptr(tagged_ptr_t tp)
{
    return (queue_node_t *)(tp.value & QUEUE_PTR_MASK);
}

/**
 * get_tag
 * Extract the version tag from a tagged pointer.
 * @param tp the tagged pointer
 * @return version counter
 */
static inline uintptr_t get_tag(tagged_ptr_t tp)
{
    return (tp.value & QUEUE_TAG_MASK) >> (sizeof(uintptr_t) * 8 - QUEUE_TAG_BITS);
}

/**
 * tagged_ptr_equals
 * Compare two tagged pointers for equality.
 * @param a first tagged pointer
 * @param b second tagged pointer
 * @return 1 if equal, 0 otherwise
 */
static inline int tagged_ptr_equals(tagged_ptr_t a, tagged_ptr_t b)
{
    return a.value == b.value;
}

/**
 * atomic_cas_tagged_ptr
 * Atomic compare-and-swap for tagged pointers.
 * @param target pointer to atomic tagged pointer
 * @param expected pointer to expected value (updated on failure)
 * @param desired new value to store
 * @return 1 if successful, 0 if failed
 */
static inline int atomic_cas_tagged_ptr(_Atomic(tagged_ptr_t) *target, tagged_ptr_t *expected,
                                        tagged_ptr_t desired)
{
    return atomic_compare_exchange_strong(target, expected, desired);
}

/**
 * backoff
 * Exponential backoff for contention.
 * @param iteration current spin iteration
 */
static inline void backoff(int iteration)
{
    if (iteration < 10)
    {
        cpu_pause();
    }
    else if (iteration < MAX_SPIN_COUNT)
    {
        for (int i = 0; i < iteration; i++)
        {
            cpu_pause();
        }
    }
    else
    {
        sched_yield();
    }
}

/* --------------------------------------------------------------------------
 * Queue Implementation
 * -------------------------------------------------------------------------- */

queue_t *queue_new(void)
{
    queue_t *queue = (queue_t *)malloc(sizeof(queue_t));
    if (queue == NULL) return NULL;

    /* create sentinel (dummy) node */
    queue_node_t *sentinel = (queue_node_t *)malloc(sizeof(queue_node_t));
    if (sentinel == NULL)
    {
        free(queue);
        return NULL;
    }

    sentinel->data = NULL;
    atomic_store(&sentinel->next, make_tagged_ptr(NULL, 0));

    /* both head and tail point to sentinel initially */
    atomic_store(&queue->head, make_tagged_ptr(sentinel, 0));
    atomic_store(&queue->tail, make_tagged_ptr(sentinel, 0));
    atomic_store(&queue->size, 0);
    atomic_store(&queue->shutdown, 0);
    atomic_store(&queue->waiter_count, 0);

    if (pthread_mutex_init(&queue->wait_lock, NULL) != 0)
    {
        free(sentinel);
        free(queue);
        return NULL;
    }

    if (pthread_cond_init(&queue->not_empty, NULL) != 0)
    {
        pthread_mutex_destroy(&queue->wait_lock);
        free(sentinel);
        free(queue);
        return NULL;
    }

    return queue;
}

int queue_enqueue(queue_t *queue, void *data)
{
    if (queue == NULL) return -1;

    /* allocate new node */
    queue_node_t *node = (queue_node_t *)malloc(sizeof(queue_node_t));
    if (node == NULL) return -1;

    node->data = data;
    atomic_store(&node->next, make_tagged_ptr(NULL, 0));

    int spin_count = 0;
    tagged_ptr_t tail, next;

    while (1)
    {
        /* read tail and its next pointer */
        tail = atomic_load(&queue->tail);
        queue_node_t *tail_ptr = get_ptr(tail);

        next = atomic_load(&tail_ptr->next);
        queue_node_t *next_ptr = get_ptr(next);

        /* check if tail is still consistent */
        tagged_ptr_t tail_check = atomic_load(&queue->tail);
        if (!tagged_ptr_equals(tail, tail_check))
        {
            backoff(spin_count++);
            continue;
        }

        if (next_ptr == NULL)
        {
            /* tail is pointing to the last node, try to link new node */
            tagged_ptr_t new_next = make_tagged_ptr(node, get_tag(next) + 1);
            if (atomic_cas_tagged_ptr(&tail_ptr->next, &next, new_next))
            {
                /* enqueue successful, try to swing tail to new node */
                tagged_ptr_t new_tail = make_tagged_ptr(node, get_tag(tail) + 1);
                atomic_cas_tagged_ptr(&queue->tail, &tail, new_tail);
                break;
            }
        }
        else
        {
            /* tail is falling behind, try to advance it */
            tagged_ptr_t new_tail = make_tagged_ptr(next_ptr, get_tag(tail) + 1);
            atomic_cas_tagged_ptr(&queue->tail, &tail, new_tail);
        }

        backoff(spin_count++);
    }

    /* increment size */
    atomic_fetch_add(&queue->size, 1);

    /* signal waiting threads */
    if (atomic_load(&queue->waiter_count) > 0)
    {
        pthread_mutex_lock(&queue->wait_lock);
        pthread_cond_signal(&queue->not_empty);
        pthread_mutex_unlock(&queue->wait_lock);
    }

    return 0;
}

void *queue_dequeue(queue_t *queue)
{
    if (queue == NULL) return NULL;

    int spin_count = 0;
    tagged_ptr_t head, tail, next;
    void *data;

    while (1)
    {
        /* read head, tail, and head's next */
        head = atomic_load(&queue->head);
        tail = atomic_load(&queue->tail);
        queue_node_t *head_ptr = get_ptr(head);

        next = atomic_load(&head_ptr->next);
        queue_node_t *next_ptr = get_ptr(next);

        /* check consistency */
        tagged_ptr_t head_check = atomic_load(&queue->head);
        if (!tagged_ptr_equals(head, head_check))
        {
            backoff(spin_count++);
            continue;
        }

        if (head_ptr == get_ptr(tail))
        {
            /* queue appears empty or tail is falling behind */
            if (next_ptr == NULL)
            {
                /* queue is empty */
                return NULL;
            }

            /* tail is falling behind, try to advance it */
            tagged_ptr_t new_tail = make_tagged_ptr(next_ptr, get_tag(tail) + 1);
            atomic_cas_tagged_ptr(&queue->tail, &tail, new_tail);
        }
        else
        {
            /* read data before CAS, otherwise another dequeue might free the node */
            data = next_ptr->data;

            /* try to swing head to next node */
            tagged_ptr_t new_head = make_tagged_ptr(next_ptr, get_tag(head) + 1);
            if (atomic_cas_tagged_ptr(&queue->head, &head, new_head))
            {
                /* dequeue successful, free the old sentinel */
                free(head_ptr);
                atomic_fetch_sub(&queue->size, 1);
                return data;
            }
        }

        backoff(spin_count++);
    }
}

void *queue_dequeue_wait(queue_t *queue)
{
    if (queue == NULL) return NULL;

    void *data;

    /* first try lock-free dequeue */
    data = queue_dequeue(queue);
    if (data != NULL) return data;

    /* no data available, need to wait */
    pthread_mutex_lock(&queue->wait_lock);
    atomic_fetch_add(&queue->waiter_count, 1);

    while (1)
    {
        /* check shutdown flag */
        if (atomic_load(&queue->shutdown))
        {
            atomic_fetch_sub(&queue->waiter_count, 1);
            pthread_mutex_unlock(&queue->wait_lock);
            return NULL;
        }

        /* try dequeue again (might have data now) */
        data = queue_dequeue(queue);
        if (data != NULL)
        {
            atomic_fetch_sub(&queue->waiter_count, 1);
            pthread_mutex_unlock(&queue->wait_lock);
            return data;
        }

        /* wait for signal */
        pthread_cond_wait(&queue->not_empty, &queue->wait_lock);
    }
}

void *queue_peek(queue_t *queue)
{
    if (queue == NULL) return NULL;

    tagged_ptr_t head = atomic_load(&queue->head);
    queue_node_t *head_ptr = get_ptr(head);

    tagged_ptr_t next = atomic_load(&head_ptr->next);
    queue_node_t *next_ptr = get_ptr(next);

    if (next_ptr == NULL)
    {
        /* queue is empty (only sentinel) */
        return NULL;
    }

    return next_ptr->data;
}

size_t queue_size(queue_t *queue)
{
    if (queue == NULL) return 0;

    return atomic_load(&queue->size);
}

int queue_is_empty(queue_t *queue)
{
    if (queue == NULL) return -1;

    return (atomic_load(&queue->size) == 0) ? 1 : 0;
}

int queue_clear(queue_t *queue)
{
    if (queue == NULL) return -1;

    /* drain the queue */
    void *data;
    while ((data = queue_dequeue(queue)) != NULL)
    {
        /* data is discarded (not freed) */
        (void)data;
    }

    return 0;
}

int queue_foreach(queue_t *queue, void (*fn)(void *data, void *context), void *context)
{
    if (queue == NULL || fn == NULL) return -1;

    int count = 0;

    /* start from head's next (skip sentinel) */
    tagged_ptr_t head = atomic_load(&queue->head);
    queue_node_t *head_ptr = get_ptr(head);

    tagged_ptr_t current_tagged = atomic_load(&head_ptr->next);
    queue_node_t *current = get_ptr(current_tagged);

    while (current != NULL)
    {
        fn(current->data, context);
        count++;

        tagged_ptr_t next_tagged = atomic_load(&current->next);
        current = get_ptr(next_tagged);
    }

    return count;
}

void *queue_peek_at(queue_t *queue, size_t index)
{
    if (queue == NULL) return NULL;

    /* start from head's next (skip sentinel) */
    tagged_ptr_t head = atomic_load(&queue->head);
    queue_node_t *head_ptr = get_ptr(head);

    tagged_ptr_t current_tagged = atomic_load(&head_ptr->next);
    queue_node_t *current = get_ptr(current_tagged);

    size_t i = 0;
    while (current != NULL)
    {
        if (i == index)
        {
            return current->data;
        }
        i++;

        tagged_ptr_t next_tagged = atomic_load(&current->next);
        current = get_ptr(next_tagged);
    }

    return NULL;
}

void queue_free(queue_t *queue)
{
    if (queue == NULL) return;

    /* set shutdown flag */
    atomic_store(&queue->shutdown, 1);

    /* wake all waiting threads */
    pthread_mutex_lock(&queue->wait_lock);
    pthread_cond_broadcast(&queue->not_empty);
    pthread_mutex_unlock(&queue->wait_lock);

    /* wait for all waiters to exit (spin with yield) */
    while (atomic_load(&queue->waiter_count) > 0)
    {
        pthread_mutex_lock(&queue->wait_lock);
        pthread_cond_broadcast(&queue->not_empty);
        pthread_mutex_unlock(&queue->wait_lock);
        sched_yield();
    }

    /* free all nodes including sentinel */
    tagged_ptr_t head = atomic_load(&queue->head);
    queue_node_t *current = get_ptr(head);

    while (current != NULL)
    {
        tagged_ptr_t next_tagged = atomic_load(&current->next);
        queue_node_t *next = get_ptr(next_tagged);
        free(current);
        current = next;
    }

    pthread_mutex_destroy(&queue->wait_lock);
    pthread_cond_destroy(&queue->not_empty);

    free(queue);
}

void queue_free_with_data(queue_t *queue, void (*free_fn)(void *))
{
    if (queue == NULL) return;

    /* set shutdown flag */
    atomic_store(&queue->shutdown, 1);

    /* wake all waiting threads */
    pthread_mutex_lock(&queue->wait_lock);
    pthread_cond_broadcast(&queue->not_empty);
    pthread_mutex_unlock(&queue->wait_lock);

    /* wait for all waiters to exit */
    while (atomic_load(&queue->waiter_count) > 0)
    {
        pthread_mutex_lock(&queue->wait_lock);
        pthread_cond_broadcast(&queue->not_empty);
        pthread_mutex_unlock(&queue->wait_lock);
        sched_yield();
    }

    /* free all nodes including sentinel, and optionally data */
    tagged_ptr_t head = atomic_load(&queue->head);
    queue_node_t *current = get_ptr(head);
    int is_sentinel = 1;

    while (current != NULL)
    {
        tagged_ptr_t next_tagged = atomic_load(&current->next);
        queue_node_t *next = get_ptr(next_tagged);

        /* free data (skip sentinel which has NULL data) */
        if (!is_sentinel && free_fn != NULL && current->data != NULL)
        {
            free_fn(current->data);
        }

        free(current);
        current = next;
        is_sentinel = 0;
    }

    pthread_mutex_destroy(&queue->wait_lock);
    pthread_cond_destroy(&queue->not_empty);

    free(queue);
}