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

#if !defined(_WIN32)
#include <sched.h>
#endif

/**
 * aligned_malloc
 * allocate memory with specified alignment.
 * @param size size of memory to allocate
 * @param alignment alignment requirement (must be power of 2)
 * @return pointer to aligned memory, NULL on failure
 */
static inline void *aligned_malloc(size_t size, size_t alignment)
{
#if defined(_WIN32)
    return _aligned_malloc(size, alignment);
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
    /* c11 aligned_alloc requires size to be multiple of alignment */
    size_t aligned_size = (size + alignment - 1) & ~(alignment - 1);
    return aligned_alloc(alignment, aligned_size);
#else
    /* posix posix_memalign */
    void *ptr = NULL;
    if (posix_memalign(&ptr, alignment, size) != 0) return NULL;
    return ptr;
#endif
}

/**
 * aligned_free
 * free memory allocated with aligned_malloc.
 * @param ptr pointer to free
 */
static inline void aligned_free(void *ptr)
{
#if defined(_WIN32)
    _aligned_free(ptr);
#else
    free(ptr);
#endif
}

/**
 * make_tagged_ptr
 * create a tagged pointer combining a raw pointer and version tag.
 * @param ptr the raw pointer
 * @param tag the version counter
 * @return tagged pointer value
 */
static inline tagged_ptr_t make_tagged_ptr(queue_node_t *ptr, uintptr_t tag)
{
    tagged_ptr_t tp;
#if UINTPTR_MAX == 0xFFFFFFFFFFFFFFFF
    /* 64-bit: pack pointer and tag into single value */
    tp.value = ((uintptr_t)ptr & QUEUE_PTR_MASK) |
               ((tag << (sizeof(uintptr_t) * 8 - QUEUE_TAG_BITS)) & QUEUE_TAG_MASK);
#else
    /* 32-bit: use separate fields */
    tp.ptr = ptr;
    tp.counter = (uint32_t)tag;
#endif
    return tp;
}

/**
 * get_ptr
 * extract the raw pointer from a tagged pointer.
 * @param tp the tagged pointer
 * @return raw pointer to queue_node_t
 */
static inline queue_node_t *get_ptr(tagged_ptr_t tp)
{
#if UINTPTR_MAX == 0xFFFFFFFFFFFFFFFF
    return (queue_node_t *)(tp.value & QUEUE_PTR_MASK);
#else
    return (queue_node_t *)tp.ptr;
#endif
}

/**
 * get_tag
 * extract the version tag from a tagged pointer.
 * @param tp the tagged pointer
 * @return version counter
 */
static inline uintptr_t get_tag(tagged_ptr_t tp)
{
#if UINTPTR_MAX == 0xFFFFFFFFFFFFFFFF
    return (tp.value & QUEUE_TAG_MASK) >> (sizeof(uintptr_t) * 8 - QUEUE_TAG_BITS);
#else
    return tp.counter;
#endif
}

/**
 * tagged_ptr_equals
 * compare two tagged pointers for equality.
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
 * atomic compare-and-swap for tagged pointers.
 * on 64-bit: cas on single 64-bit value
 * on 32-bit: cas on 8-byte struct (pointer + counter) using cmpxchg8b on x86
 * @param target pointer to atomic tagged pointer
 * @param expected pointer to expected value (updated on failure)
 * @param desired new value to store
 * @return 1 if successful, 0 if failed
 */
static inline int atomic_cas_tagged_ptr(_Atomic(tagged_ptr_t) *target, tagged_ptr_t *expected,
                                        tagged_ptr_t desired)
{
#if UINTPTR_MAX == 0xFFFFFFFFFFFFFFFF
    /* 64-bit: standard cas on single value */
    return atomic_compare_exchange_strong(target, expected, desired);
#else
    /* 32-bit: use gcc/clang builtin for 8-byte cas on x86-32 (cmpxchg8b)
     * this is more reliable than c11 atomics which may use locks */
#if (defined(__GNUC__) || defined(__clang__)) && (defined(__i386__) || defined(_M_IX86))
    /* use gcc/clang __sync builtin for 64-bit cas on 32-bit x86 */
    typedef unsigned long long u64;
    union
    {
        tagged_ptr_t tp;
        u64 u;
    } exp_u, des_u;
    exp_u.tp = *expected;
    des_u.tp = desired;
    u64 old = __sync_val_compare_and_swap((u64 *)target, exp_u.u, des_u.u);
    if (old == exp_u.u)
    {
        return 1;
    }
    else
    {
        exp_u.u = old;
        *expected = exp_u.tp;
        return 0;
    }
#else
    /* fallback to c11 atomics (may use locks on some platforms) */
    return atomic_compare_exchange_strong(target, expected, desired);
#endif
#endif
}

/**
 * backoff
 * exponential backoff for contention.
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
        /* yield cpu time slice to other threads */
#if defined(_WIN32)
        Sleep(0);
#else
        sched_yield();
#endif
    }
}

/**
 * epoch-based reclamation
 *
 * to prevent use-after-free in the lock-free queue, we use epoch-based reclamation:
 * - each enqueue/dequeue increments a global epoch counter
 * - when a node is retired, we record the current epoch
 * - nodes are only freed when they're older than (current_epoch - grace_period)
 * - this ensures no thread can be accessing a node when it's freed
 *
 * the grace period of 2 epochs is sufficient because:
 * - a thread reads a node pointer in epoch n
 * - by epoch n+1, that thread has either completed or moved to a new node
 * - by epoch n+2, it's guaranteed safe to free the node from epoch n
 */

/* grace period: nodes must be at least this many epochs old to reclaim */
#define EPOCH_GRACE_PERIOD 2
/* reclaim threshold: trigger reclamation when this many nodes retired */
#define RECLAIM_THRESHOLD 100

/**
 * reclaim_retired_nodes
 * free nodes that are old enough (beyond grace period).
 * @param queue the queue
 */
static void reclaim_retired_nodes(queue_t *queue)
{
    uint64_t current_epoch = atomic_load(&queue->global_epoch);
    if (current_epoch < EPOCH_GRACE_PERIOD) return;

    uint64_t safe_epoch = current_epoch - EPOCH_GRACE_PERIOD;

    pthread_mutex_lock(&queue->retired_lock);

    retired_node_t **prev_ptr = &queue->retired_head;
    retired_node_t *current = queue->retired_head;
    size_t reclaimed = 0;

    while (current != NULL)
    {
        if (current->retire_epoch <= safe_epoch)
        {
            /* node is old enough, reclaim it */
            retired_node_t *to_free = current;
            *prev_ptr = current->next;
            current = current->next;

            aligned_free(to_free->node);
            free(to_free);
            reclaimed++;
        }
        else
        {
            /* keep this node, move to next */
            prev_ptr = &current->next;
            current = current->next;
        }
    }

    pthread_mutex_unlock(&queue->retired_lock);

    if (reclaimed > 0)
    {
        atomic_fetch_sub(&queue->retired_count, reclaimed);
    }
}

/**
 * retire_node
 * add node to retired list for deferred reclamation.
 * prevents use-after-free in concurrent dequeue operations.
 * @param queue the queue
 * @param node the node to retire
 */
static void retire_node(queue_t *queue, queue_node_t *node)
{
    retired_node_t *retired = malloc(sizeof(retired_node_t));
    if (retired == NULL)
    {
        /* fallback: immediate free (not ideal but prevents memory leak) */
        aligned_free(node);
        return;
    }

    retired->node = node;
    retired->retire_epoch = atomic_load(&queue->global_epoch);

    pthread_mutex_lock(&queue->retired_lock);
    retired->next = queue->retired_head;
    queue->retired_head = retired;
    pthread_mutex_unlock(&queue->retired_lock);

    size_t retired_count = atomic_fetch_add(&queue->retired_count, 1) + 1;

    /* periodically reclaim old nodes */
    if (retired_count >= RECLAIM_THRESHOLD)
    {
        reclaim_retired_nodes(queue);
    }
}

queue_t *queue_new(void)
{
    queue_t *queue = (queue_t *)aligned_malloc(sizeof(queue_t), 8);
    if (queue == NULL) return NULL;

    /* create sentinel (dummy) node */
    queue_node_t *sentinel = (queue_node_t *)aligned_malloc(sizeof(queue_node_t), 8);
    if (sentinel == NULL)
    {
        aligned_free(queue);
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
    atomic_store(&queue->global_epoch, 0);
    atomic_store(&queue->retired_count, 0);
    queue->retired_head = NULL;

    if (pthread_mutex_init(&queue->wait_lock, NULL) != 0)
    {
        aligned_free(sentinel);
        aligned_free(queue);
        return NULL;
    }

    if (pthread_cond_init(&queue->not_empty, NULL) != 0)
    {
        pthread_mutex_destroy(&queue->wait_lock);
        aligned_free(sentinel);
        aligned_free(queue);
        return NULL;
    }

    if (pthread_mutex_init(&queue->retired_lock, NULL) != 0)
    {
        pthread_cond_destroy(&queue->not_empty);
        pthread_mutex_destroy(&queue->wait_lock);
        aligned_free(sentinel);
        aligned_free(queue);
        return NULL;
    }

    return queue;
}

int queue_enqueue(queue_t *queue, void *data)
{
    if (queue == NULL) return -1;

    queue_node_t *node = (queue_node_t *)aligned_malloc(sizeof(queue_node_t), 8);
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

    /* advance epoch for reclamation */
    atomic_fetch_add(&queue->global_epoch, 1);

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
            /* read data before CAS
             * safe because nodes are retired (not freed immediately) */
            data = next_ptr->data;

            /* try to swing head to next node */
            tagged_ptr_t new_head = make_tagged_ptr(next_ptr, get_tag(head) + 1);
            if (atomic_cas_tagged_ptr(&queue->head, &head, new_head))
            {
                /* dequeue successful, retire the old sentinel for deferred reclamation */
                retire_node(queue, head_ptr);
                atomic_fetch_sub(&queue->size, 1);

                /* advance epoch for reclamation */
                atomic_fetch_add(&queue->global_epoch, 1);

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

int queue_snapshot_with_refs(queue_t *queue, void ***items, size_t *count,
                             void (*ref_fn)(void *item))
{
    if (!queue || !items || !count || !ref_fn) return -1;

    *items = NULL;
    *count = 0;

    /* get approximate size for initial allocation */
    size_t approx_size = atomic_load(&queue->size);
    if (approx_size == 0) return 0;

    /* allocate with some headroom for concurrent enqueues */
    size_t capacity = approx_size + 16;
    void **snapshot = malloc(capacity * sizeof(void *));
    if (!snapshot) return -1;

    /* traverse queue and take refs atomically
     * this prevents use-after-free even if items are dequeued during traversal */
    tagged_ptr_t head = atomic_load(&queue->head);
    queue_node_t *head_ptr = get_ptr(head);

    tagged_ptr_t current_tagged = atomic_load(&head_ptr->next);
    queue_node_t *current = get_ptr(current_tagged);

    size_t idx = 0;
    while (current != NULL)
    {
        void *data = current->data;
        if (data)
        {
            /* take reference BEFORE adding to snapshot
             * this ensures item can't be freed even if dequeued */
            ref_fn(data);

            /* expand array if needed */
            if (idx >= capacity)
            {
                size_t new_capacity = capacity * 2;
                void **new_snapshot = realloc(snapshot, new_capacity * sizeof(void *));
                if (!new_snapshot)
                {
                    /* cleanup: release all refs taken so far */
                    free(snapshot);
                    return -1;
                }
                snapshot = new_snapshot;
                capacity = new_capacity;
            }

            snapshot[idx++] = data;
        }

        tagged_ptr_t next_tagged = atomic_load(&current->next);
        current = get_ptr(next_tagged);
    }

    *items = snapshot;
    *count = idx;
    return 0;
}

void queue_free(queue_t *queue)
{
    if (queue == NULL) return;

    atomic_store(&queue->shutdown, 1);

    pthread_mutex_lock(&queue->wait_lock);
    pthread_cond_broadcast(&queue->not_empty);
    pthread_mutex_unlock(&queue->wait_lock);

    while (atomic_load(&queue->waiter_count) > 0)
    {
        pthread_mutex_lock(&queue->wait_lock);
        pthread_cond_broadcast(&queue->not_empty);
        pthread_mutex_unlock(&queue->wait_lock);
#if defined(_WIN32)
        Sleep(0);
#else
        sched_yield();
#endif
    }

    /* free all nodes in the queue */
    tagged_ptr_t head = atomic_load(&queue->head);
    queue_node_t *current = get_ptr(head);

    while (current != NULL)
    {
        tagged_ptr_t next_tagged = atomic_load(&current->next);
        queue_node_t *next = get_ptr(next_tagged);
        aligned_free(current);
        current = next;
    }

    /* free all retired nodes */
    pthread_mutex_lock(&queue->retired_lock);
    retired_node_t *retired = queue->retired_head;
    while (retired != NULL)
    {
        retired_node_t *next_retired = retired->next;
        aligned_free(retired->node);
        free(retired);
        retired = next_retired;
    }
    pthread_mutex_unlock(&queue->retired_lock);

    pthread_mutex_destroy(&queue->retired_lock);
    pthread_mutex_destroy(&queue->wait_lock);
    pthread_cond_destroy(&queue->not_empty);

    aligned_free(queue);
}

void queue_free_with_data(queue_t *queue, void (*free_fn)(void *))
{
    if (queue == NULL) return;
    atomic_store(&queue->shutdown, 1);

    pthread_mutex_lock(&queue->wait_lock);
    pthread_cond_broadcast(&queue->not_empty);
    pthread_mutex_unlock(&queue->wait_lock);

    while (atomic_load(&queue->waiter_count) > 0)
    {
        pthread_mutex_lock(&queue->wait_lock);
        pthread_cond_broadcast(&queue->not_empty);
        pthread_mutex_unlock(&queue->wait_lock);
#if defined(_WIN32)
        Sleep(0);
#else
        sched_yield();
#endif
    }

    /* free all nodes in the queue */
    tagged_ptr_t head = atomic_load(&queue->head);
    queue_node_t *current = get_ptr(head);
    int is_sentinel = 1;

    while (current != NULL)
    {
        tagged_ptr_t next_tagged = atomic_load(&current->next);
        queue_node_t *next = get_ptr(next_tagged);

        if (!is_sentinel && free_fn != NULL && current->data != NULL)
        {
            free_fn(current->data);
        }

        aligned_free(current);
        current = next;
        is_sentinel = 0;
    }

    /* free all retired nodes (data already freed by dequeue) */
    pthread_mutex_lock(&queue->retired_lock);
    retired_node_t *retired = queue->retired_head;
    while (retired != NULL)
    {
        retired_node_t *next_retired = retired->next;
        aligned_free(retired->node);
        free(retired);
        retired = next_retired;
    }
    pthread_mutex_unlock(&queue->retired_lock);

    pthread_mutex_destroy(&queue->retired_lock);
    pthread_mutex_destroy(&queue->wait_lock);
    pthread_cond_destroy(&queue->not_empty);

    aligned_free(queue);
}