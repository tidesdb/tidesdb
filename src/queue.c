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

#define QUEUE_LIKELY(x)   TDB_LIKELY(x)
#define QUEUE_UNLIKELY(x) TDB_UNLIKELY(x)

#define QUEUE_WAIT_TIMEOUT_NS 100000000  /* 100ms in nanoseconds */
#define QUEUE_NS_PER_SEC      1000000000 /* nanoseconds per second */

/**
 * queue_alloc_node
 * allocate a node from pool or heap
 * pool access is protected by pool_lock for thread safety
 * @param queue the queue to allocate the node from
 * @return the allocated node, or NULL on failure
 */
static inline queue_node_t *queue_alloc_node(queue_t *queue)
{
    if (QUEUE_UNLIKELY(atomic_load_explicit(&queue->pool_size, memory_order_relaxed) == 0))
    {
        return (queue_node_t *)malloc(sizeof(queue_node_t));
    }

    pthread_mutex_lock(&queue->pool_lock);

    /* we check pool first (common case) */
    if (QUEUE_LIKELY(queue->node_pool != NULL))
    {
        queue_node_t *node = queue->node_pool;
        queue->node_pool = node->next;
        /* load+store avoids lock-prefixed instruction; mutex provides ordering */
        const size_t ps = atomic_load_explicit(&queue->pool_size, memory_order_relaxed);
        atomic_store_explicit(&queue->pool_size, ps - 1, memory_order_relaxed);
        pthread_mutex_unlock(&queue->pool_lock);
        return node;
    }

    pthread_mutex_unlock(&queue->pool_lock);

    /* pool empty, allocate from heap */
    return (queue_node_t *)malloc(sizeof(queue_node_t));
}

/**
 * queue_free_node
 * return node to pool or free it
 * pool access is protected by pool_lock for thread safety
 * @param queue the queue to return the node to
 * @param node the node to return
 */
static inline void queue_free_node(queue_t *queue, queue_node_t *node)
{
    /* speculative lock-free check -- skip mutex when pool is full
     * racy read is safe           -- worst case we free when pool had room */
    if (QUEUE_UNLIKELY(atomic_load_explicit(&queue->pool_size, memory_order_relaxed) >=
                       queue->max_pool_size))
    {
        free(node);
        return;
    }

    pthread_mutex_lock(&queue->pool_lock);

    const size_t ps = atomic_load_explicit(&queue->pool_size, memory_order_relaxed);
    if (QUEUE_LIKELY(ps < queue->max_pool_size))
    {
        /* return to pool */
        node->next = queue->node_pool;
        queue->node_pool = node;
        /* load+store avoids lock-prefixed instruction; mutex provides ordering */
        atomic_store_explicit(&queue->pool_size, ps + 1, memory_order_relaxed);
        pthread_mutex_unlock(&queue->pool_lock);
        return;
    }

    pthread_mutex_unlock(&queue->pool_lock);

    /* pool full, actually free */
    free(node);
}

queue_t *queue_new(void)
{
    queue_t *queue = (queue_t *)malloc(sizeof(queue_t));
    if (queue == NULL) return NULL;

    /* we create a dummy node to separate head and tail
     * this allows enqueue and dequeue to operate independently */
    queue_node_t *dummy = (queue_node_t *)malloc(sizeof(queue_node_t));
    if (dummy == NULL)
    {
        free(queue);
        return NULL;
    }
    dummy->data = NULL;
    dummy->next = NULL;

    queue->head = dummy;
    queue->tail = dummy;
    queue->dummy = dummy;
    atomic_store_explicit(&queue->size, 0, memory_order_relaxed);
    atomic_store_explicit(&queue->shutdown, 0, memory_order_relaxed);
    atomic_store_explicit(&queue->waiter_count, 0, memory_order_relaxed);
    queue->node_pool = NULL;
    atomic_store_explicit(&queue->pool_size, 0, memory_order_relaxed);
    queue->max_pool_size = QUEUE_MAX_POOL_SIZE;

    if (pthread_mutex_init(&queue->head_lock, NULL) != 0)
    {
        free(dummy);
        free(queue);
        return NULL;
    }

    if (pthread_mutex_init(&queue->tail_lock, NULL) != 0)
    {
        pthread_mutex_destroy(&queue->head_lock);
        free(dummy);
        free(queue);
        return NULL;
    }

    if (pthread_mutex_init(&queue->pool_lock, NULL) != 0)
    {
        pthread_mutex_destroy(&queue->tail_lock);
        pthread_mutex_destroy(&queue->head_lock);
        free(dummy);
        free(queue);
        return NULL;
    }

    if (pthread_rwlock_init(&queue->read_lock, NULL) != 0)
    {
        pthread_mutex_destroy(&queue->pool_lock);
        pthread_mutex_destroy(&queue->tail_lock);
        pthread_mutex_destroy(&queue->head_lock);
        free(dummy);
        free(queue);
        return NULL;
    }

    if (pthread_cond_init(&queue->not_empty, NULL) != 0)
    {
        pthread_rwlock_destroy(&queue->read_lock);
        pthread_mutex_destroy(&queue->pool_lock);
        pthread_mutex_destroy(&queue->tail_lock);
        pthread_mutex_destroy(&queue->head_lock);
        free(dummy);
        free(queue);
        return NULL;
    }

    return queue;
}

int queue_enqueue(queue_t *queue, void *data)
{
    if (QUEUE_UNLIKELY(queue == NULL)) return -1;

    queue_node_t *node = queue_alloc_node(queue);
    if (QUEUE_UNLIKELY(node == NULL))
    {
        return -1;
    }

    node->data = data;
    node->next = NULL;

    /* we only lock tail for enqueue -- the head operations are independent */
    pthread_mutex_lock(&queue->tail_lock);

    queue->tail->next = node;
    queue->tail = node;

    /* we check if we need to signal before releasing lock */
    const size_t old_size = atomic_fetch_add_explicit(&queue->size, 1, memory_order_release);
    const int has_waiters = atomic_load_explicit(&queue->waiter_count, memory_order_acquire) > 0;

    pthread_mutex_unlock(&queue->tail_lock);

    /* we signal outside lock to reduce lock hold time
     * only signal if queue was empty and there are waiters */
    if (old_size == 0 && has_waiters)
    {
        pthread_mutex_lock(&queue->head_lock);
        pthread_cond_signal(&queue->not_empty);
        pthread_mutex_unlock(&queue->head_lock);
    }

    return 0;
}

/**
 * queue_dequeue_internal
 * internal helper for dequeue logic (head_lock must be held)
 * uses dummy node technique for lock-free separation of head and tail
 * @param queue the queue
 * @return pointer to dequeued data, NULL if queue is empty
 */
static inline void *queue_dequeue_internal(queue_t *queue)
{
    queue_node_t *old_head = queue->head;
    queue_node_t *new_head = old_head->next;

    /* if next is NULL, queue is empty */
    if (QUEUE_UNLIKELY(new_head == NULL))
    {
        return NULL;
    }

    /* we advance head to next node (which becomes new dummy) */
    void *data = new_head->data;
    new_head->data = NULL; /* clear data since this node becomes the new dummy */
    queue->head = new_head;

    atomic_fetch_sub_explicit(&queue->size, 1, memory_order_relaxed);

    /* return old dummy node to pool */
    queue_free_node(queue, old_head);

    return data;
}

void *queue_dequeue(queue_t *queue)
{
    if (QUEUE_UNLIKELY(queue == NULL)) return NULL;

    pthread_rwlock_wrlock(&queue->read_lock);
    pthread_mutex_lock(&queue->head_lock);
    void *data = queue_dequeue_internal(queue);
    pthread_mutex_unlock(&queue->head_lock);
    pthread_rwlock_unlock(&queue->read_lock);

    return data;
}

void *queue_dequeue_wait(queue_t *queue)
{
    if (QUEUE_UNLIKELY(queue == NULL)) return NULL;

    /* we spin briefly before blocking to avoid syscall overhead */
    for (int i = 0; i < QUEUE_SPIN_COUNT; i++)
    {
        if (atomic_load_explicit(&queue->size, memory_order_acquire) > 0)
        {
            pthread_rwlock_wrlock(&queue->read_lock);
            pthread_mutex_lock(&queue->head_lock);
            void *data = queue_dequeue_internal(queue);
            pthread_mutex_unlock(&queue->head_lock);
            pthread_rwlock_unlock(&queue->read_lock);
            if (data != NULL)
            {
                return data;
            }
        }
        cpu_pause();
    }

    /* we fall back to blocking wait */
    pthread_mutex_lock(&queue->head_lock);

    atomic_fetch_add_explicit(&queue->waiter_count, 1, memory_order_relaxed);

    while (queue->head->next == NULL &&
           !atomic_load_explicit(&queue->shutdown, memory_order_acquire))
    {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += QUEUE_WAIT_TIMEOUT_NS;
        if (ts.tv_nsec >= QUEUE_NS_PER_SEC)
        {
            ts.tv_sec += 1;
            ts.tv_nsec -= QUEUE_NS_PER_SEC;
        }
        pthread_cond_timedwait(&queue->not_empty, &queue->head_lock, &ts);
    }

    const int remaining_waiters =
        atomic_fetch_sub_explicit(&queue->waiter_count, 1, memory_order_relaxed) - 1;

    /* we broadcast when last waiter exits to wake queue_free if waiting */
    if (remaining_waiters == 0)
    {
        pthread_cond_broadcast(&queue->not_empty);
    }

    /* if shutdown and no data, return NULL */
    if (QUEUE_UNLIKELY(atomic_load_explicit(&queue->shutdown, memory_order_acquire) &&
                       queue->head->next == NULL))
    {
        pthread_mutex_unlock(&queue->head_lock);
        return NULL;
    }

    /*** we acquire write lock to coordinate with readers, then dequeue
     **  we must re-check for data after re-acquiring locks since another thread
     *   could have stolen the item while we released head_lock */
    while (1)
    {
        pthread_mutex_unlock(&queue->head_lock);
        pthread_rwlock_wrlock(&queue->read_lock);
        pthread_mutex_lock(&queue->head_lock);

        /** we check if data is still available */
        if (queue->head->next != NULL)
        {
            void *data = queue_dequeue_internal(queue);
            pthread_mutex_unlock(&queue->head_lock);
            pthread_rwlock_unlock(&queue->read_lock);
            return data;
        }

        /* data was stolen! release locks and wait again */
        pthread_rwlock_unlock(&queue->read_lock);

        if (atomic_load_explicit(&queue->shutdown, memory_order_acquire))
        {
            pthread_mutex_unlock(&queue->head_lock);
            return NULL;
        }

        /* we increment waiter count and wait for more data */
        atomic_fetch_add_explicit(&queue->waiter_count, 1, memory_order_relaxed);

        while (queue->head->next == NULL &&
               !atomic_load_explicit(&queue->shutdown, memory_order_acquire))
        {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_nsec += QUEUE_WAIT_TIMEOUT_NS;
            if (ts.tv_nsec >= QUEUE_NS_PER_SEC)
            {
                ts.tv_sec += 1;
                ts.tv_nsec -= QUEUE_NS_PER_SEC;
            }
            pthread_cond_timedwait(&queue->not_empty, &queue->head_lock, &ts);
        }

        atomic_fetch_sub_explicit(&queue->waiter_count, 1, memory_order_relaxed);

        /* we check for shutdown after waking */
        if (atomic_load_explicit(&queue->shutdown, memory_order_acquire) &&
            queue->head->next == NULL)
        {
            pthread_mutex_unlock(&queue->head_lock);
            return NULL;
        }
    }
}

void *queue_peek(queue_t *queue)
{
    if (QUEUE_UNLIKELY(queue == NULL)) return NULL;

    pthread_rwlock_rdlock(&queue->read_lock);

    void *data = NULL;
    /* with dummy node, actual data is in head->next */
    if (QUEUE_LIKELY(queue->head->next != NULL))
    {
        data = queue->head->next->data;
    }

    pthread_rwlock_unlock(&queue->read_lock);

    return data;
}

size_t queue_size(queue_t *queue)
{
    if (queue == NULL) return 0;

    return atomic_load_explicit(&queue->size, memory_order_relaxed);
}

int queue_is_empty(queue_t *queue)
{
    if (queue == NULL) return -1;

    return (atomic_load_explicit(&queue->size, memory_order_relaxed) == 0) ? 1 : 0;
}

int queue_clear(queue_t *queue)
{
    if (QUEUE_UNLIKELY(queue == NULL)) return -1;

    /* we lock write lock first, then both head and tail to ensure exclusive access */
    pthread_rwlock_wrlock(&queue->read_lock);
    pthread_mutex_lock(&queue->head_lock);
    pthread_mutex_lock(&queue->tail_lock);

    /* we free all nodes after the dummy */
    queue_node_t *current = queue->head->next;
    while (current != NULL)
    {
        queue_node_t *next = current->next;
        queue_free_node(queue, current);
        current = next;
    }

    /* we reset to empty state with just the dummy */
    queue->head->next = NULL;
    queue->tail = queue->head;
    atomic_store_explicit(&queue->size, 0, memory_order_relaxed);

    pthread_mutex_unlock(&queue->tail_lock);
    pthread_mutex_unlock(&queue->head_lock);
    pthread_rwlock_unlock(&queue->read_lock);

    return 0;
}

int queue_foreach(queue_t *queue, void (*fn)(void *data, void *context), void *context)
{
    if (QUEUE_UNLIKELY(queue == NULL)) return -1;
    if (QUEUE_UNLIKELY(fn == NULL)) return -1;

    pthread_rwlock_rdlock(&queue->read_lock);

    int count = 0;
    const queue_node_t *current = queue->head->next;
    while (QUEUE_LIKELY(current != NULL))
    {
        if (QUEUE_LIKELY(current->next != NULL))
        {
            PREFETCH_READ(current->next);
        }
        fn(current->data, context);
        count++;
        current = current->next;
    }

    pthread_rwlock_unlock(&queue->read_lock);

    return count;
}

void *queue_peek_at(queue_t *queue, const size_t index)
{
    if (QUEUE_UNLIKELY(!queue)) return NULL;

    if (index >= atomic_load_explicit(&queue->size, memory_order_relaxed))
    {
        return NULL;
    }

    pthread_rwlock_rdlock(&queue->read_lock);

    /* with dummy node, actual data starts at head->next */
    const queue_node_t *current = queue->head->next;
    for (size_t i = 0; i < index && QUEUE_LIKELY(current != NULL); i++)
    {
        /* we prefetch next node to overlap memory latency with loop iteration */
        if (QUEUE_LIKELY(current->next != NULL))
        {
            PREFETCH_READ(current->next);
        }
        current = current->next;
    }

    void *data = QUEUE_LIKELY(current != NULL) ? current->data : NULL;

    pthread_rwlock_unlock(&queue->read_lock);

    return data;
}

void queue_shutdown(queue_t *queue)
{
    if (queue == NULL) return;

    /* we set shutdown flag and wake all waiting threads */
    atomic_store_explicit(&queue->shutdown, 1, memory_order_release);

    pthread_mutex_lock(&queue->head_lock);
    pthread_cond_broadcast(&queue->not_empty);
    pthread_mutex_unlock(&queue->head_lock);
}

void queue_free(queue_t *queue)
{
    queue_free_with_data(queue, NULL);
}

void queue_free_with_data(queue_t *queue, void (*free_fn)(void *))
{
    if (queue == NULL) return;

    /* we set shutdown flag and wake all waiting threads */
    atomic_store_explicit(&queue->shutdown, 1, memory_order_release);

    pthread_mutex_lock(&queue->head_lock);
    pthread_cond_broadcast(&queue->not_empty);

    /* we wait for all waiting threads to exit before destroying primitives
     * we use timed wait to handle BSD platforms where signals can be missed */
    while (atomic_load_explicit(&queue->waiter_count, memory_order_acquire) > 0)
    {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += QUEUE_WAIT_TIMEOUT_NS;
        if (ts.tv_nsec >= QUEUE_NS_PER_SEC)
        {
            ts.tv_sec += 1;
            ts.tv_nsec -= QUEUE_NS_PER_SEC;
        }
        pthread_cond_timedwait(&queue->not_empty, &queue->head_lock, &ts);
    }

    pthread_mutex_lock(&queue->tail_lock);

    /* we free all nodes including the dummy, freeing user data */
    queue_node_t *current = queue->head;
    while (current != NULL)
    {
        queue_node_t *next = current->next;
        if (free_fn != NULL && current->data != NULL)
        {
            free_fn(current->data);
        }
        free(current);
        current = next;
    }

    pthread_mutex_lock(&queue->pool_lock);
    current = queue->node_pool;
    while (current != NULL)
    {
        queue_node_t *next = current->next;
        free(current);
        current = next;
    }
    queue->node_pool = NULL;
    pthread_mutex_unlock(&queue->pool_lock);

    queue->head = NULL;
    queue->tail = NULL;
    queue->dummy = NULL;
    atomic_store_explicit(&queue->size, 0, memory_order_relaxed);

    pthread_mutex_unlock(&queue->tail_lock);
    pthread_mutex_unlock(&queue->head_lock);

    pthread_mutex_destroy(&queue->pool_lock);
    pthread_rwlock_destroy(&queue->read_lock);
    pthread_mutex_destroy(&queue->tail_lock);
    pthread_mutex_destroy(&queue->head_lock);
    pthread_cond_destroy(&queue->not_empty);

    free(queue);
}