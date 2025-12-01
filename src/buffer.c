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
#include "buffer.h"

int buffer_new(buffer_t **buffer, uint32_t capacity)
{
    return buffer_new_with_eviction(buffer, capacity, NULL, NULL);
}

int buffer_new_with_eviction(buffer_t **buffer, uint32_t capacity, buffer_eviction_fn eviction_fn,
                             void *eviction_ctx)
{
    if (buffer == NULL || capacity == 0) return -1;

    buffer_t *new_buffer = (buffer_t *)malloc(sizeof(buffer_t));
    if (new_buffer == NULL) return -1;

    new_buffer->slots = (buffer_slot_t *)malloc(capacity * sizeof(buffer_slot_t));
    if (new_buffer->slots == NULL)
    {
        free(new_buffer);
        return -1;
    }

    new_buffer->capacity = capacity;
    new_buffer->eviction_fn = eviction_fn;
    new_buffer->eviction_ctx = eviction_ctx;
    new_buffer->max_retries = BUFFER_DEFAULT_MAX_RETRIES;
    new_buffer->backoff_us = BUFFER_DEFAULT_BACKOFF_US;

    atomic_init(&new_buffer->hint_index, 0);
    atomic_init(&new_buffer->active_count, 0);

    for (uint32_t i = 0; i < capacity; i++)
    {
        atomic_init(&new_buffer->slots[i].state, BUFFER_SLOT_FREE);
        atomic_init(&new_buffer->slots[i].generation, 0);
        atomic_init(&new_buffer->slots[i].data, NULL);
    }

    *buffer = new_buffer;
    return 0;
}

int buffer_set_retry_params(buffer_t *buffer, uint32_t max_retries, uint32_t backoff_us)
{
    if (buffer == NULL) return -1;
    buffer->max_retries = max_retries;
    buffer->backoff_us = backoff_us;
    return 0;
}

/**
 * try_acquire_slot
 * attempts to acquire a specific slot
 * @return 0 on success, -1 if slot not free
 */
static int try_acquire_slot(buffer_t *buffer, uint32_t index, void *data, uint32_t *id)
{
    buffer_slot_t *slot = &buffer->slots[index];

    /* try to transition FREE -> ACQUIRED */
    uint32_t expected = BUFFER_SLOT_FREE;
    if (!atomic_compare_exchange_strong_explicit(&slot->state, &expected, BUFFER_SLOT_ACQUIRED,
                                                 memory_order_acquire, memory_order_relaxed))
    {
        return -1; /* slot not free */
    }

    /* we own the slot now, set data and transition to OCCUPIED */
    atomic_store_explicit(&slot->data, data, memory_order_relaxed);

    /* increment generation for ABA prevention */
    atomic_fetch_add_explicit(&slot->generation, 1, memory_order_relaxed);

    /* transition ACQUIRED -> OCCUPIED */
    atomic_store_explicit(&slot->state, BUFFER_SLOT_OCCUPIED, memory_order_release);

    /* update active count */
    atomic_fetch_add_explicit(&buffer->active_count, 1, memory_order_relaxed);

    *id = index;
    return 0;
}

int buffer_try_acquire(buffer_t *buffer, void *data, uint32_t *id)
{
    if (buffer == NULL || id == NULL) return -1;

    uint32_t capacity = buffer->capacity;
    uint32_t start = atomic_load_explicit(&buffer->hint_index, memory_order_relaxed) % capacity;

    /* scan from hint position */
    for (uint32_t i = 0; i < capacity; i++)
    {
        uint32_t index = (start + i) % capacity;

        if (try_acquire_slot(buffer, index, data, id) == 0)
        {
            /* update hint to next slot for future searches */
            atomic_store_explicit(&buffer->hint_index, (index + 1) % capacity,
                                  memory_order_relaxed);
            return 0;
        }
    }

    *id = BUFFER_INVALID_ID;
    return -1; /* no free slots */
}

int buffer_acquire(buffer_t *buffer, void *data, uint32_t *id)
{
    if (buffer == NULL || id == NULL) return -1;

    uint32_t retries = 0;
    uint32_t backoff = buffer->backoff_us;

    while (buffer->max_retries == 0 || retries < buffer->max_retries)
    {
        if (buffer_try_acquire(buffer, data, id) == 0)
        {
            return 0;
        }

        /* exponential backoff with cap */
        if (backoff > 0)
        {
            if (backoff < 1000)
            {
                /* short backoff: just pause */
                for (uint32_t i = 0; i < backoff; i++)
                {
                    cpu_pause();
                }
            }
            else
            {
                usleep(backoff);
            }

            /* exponential increase, capped at 10ms */
            if (backoff < 10000)
            {
                backoff *= 2;
            }
        }
        else
        {
            cpu_pause();
        }

        retries++;
    }

    *id = BUFFER_INVALID_ID;
    return -1; /* max retries exceeded */
}

int buffer_get(buffer_t *buffer, uint32_t id, void **data)
{
    if (buffer == NULL || data == NULL) return -1;
    if (id >= buffer->capacity) return -1;

    buffer_slot_t *slot = &buffer->slots[id];
    uint32_t state = atomic_load_explicit(&slot->state, memory_order_acquire);

    if (state != BUFFER_SLOT_OCCUPIED)
    {
        *data = NULL;
        return -1;
    }

    *data = atomic_load_explicit(&slot->data, memory_order_acquire);
    return 0;
}

int buffer_release(buffer_t *buffer, uint32_t id)
{
    if (buffer == NULL) return -1;
    if (id >= buffer->capacity) return -1;

    buffer_slot_t *slot = &buffer->slots[id];

    /* try to transition OCCUPIED -> RELEASING */
    uint32_t expected = BUFFER_SLOT_OCCUPIED;
    if (!atomic_compare_exchange_strong_explicit(&slot->state, &expected, BUFFER_SLOT_RELEASING,
                                                 memory_order_acquire, memory_order_relaxed))
    {
        return -1; /* slot not occupied or already being released */
    }

    /* get data for eviction callback */
    void *data = atomic_load_explicit(&slot->data, memory_order_relaxed);

    /* call eviction callback if set */
    if (buffer->eviction_fn != NULL && data != NULL)
    {
        buffer->eviction_fn(data, buffer->eviction_ctx);
    }

    /* clear data */
    atomic_store_explicit(&slot->data, NULL, memory_order_relaxed);

    /* transition RELEASING -> FREE */
    atomic_store_explicit(&slot->state, BUFFER_SLOT_FREE, memory_order_release);

    /* update active count */
    atomic_fetch_sub_explicit(&buffer->active_count, 1, memory_order_relaxed);

    return 0;
}

int buffer_release_silent(buffer_t *buffer, uint32_t id)
{
    if (buffer == NULL) return -1;
    if (id >= buffer->capacity) return -1;

    buffer_slot_t *slot = &buffer->slots[id];

    /* try to transition OCCUPIED -> RELEASING */
    uint32_t expected = BUFFER_SLOT_OCCUPIED;
    if (!atomic_compare_exchange_strong_explicit(&slot->state, &expected, BUFFER_SLOT_RELEASING,
                                                 memory_order_acquire, memory_order_relaxed))
    {
        return -1;
    }

    /* clear data without calling eviction */
    atomic_store_explicit(&slot->data, NULL, memory_order_relaxed);

    /* transition RELEASING -> FREE */
    atomic_store_explicit(&slot->state, BUFFER_SLOT_FREE, memory_order_release);

    /* update active count */
    atomic_fetch_sub_explicit(&buffer->active_count, 1, memory_order_relaxed);

    return 0;
}

int buffer_is_occupied(buffer_t *buffer, uint32_t id)
{
    if (buffer == NULL) return -1;
    if (id >= buffer->capacity) return -1;

    uint32_t state = atomic_load_explicit(&buffer->slots[id].state, memory_order_acquire);
    return (state == BUFFER_SLOT_OCCUPIED) ? 1 : 0;
}

int buffer_active_count(buffer_t *buffer)
{
    if (buffer == NULL) return -1;
    return (int)atomic_load_explicit(&buffer->active_count, memory_order_acquire);
}

int buffer_capacity(buffer_t *buffer)
{
    if (buffer == NULL) return -1;
    return (int)buffer->capacity;
}

int buffer_clear(buffer_t *buffer)
{
    if (buffer == NULL) return -1;

    for (uint32_t i = 0; i < buffer->capacity; i++)
    {
        /* try to release each occupied slot */
        buffer_release(buffer, i);
    }

    return 0;
}

void buffer_free(buffer_t *buffer)
{
    if (buffer == NULL) return;

    /* release all occupied slots */
    buffer_clear(buffer);

    free(buffer->slots);
    free(buffer);
    buffer = NULL;
}

int buffer_foreach(buffer_t *buffer, void (*callback)(uint32_t id, void *data, void *ctx),
                   void *ctx)
{
    if (buffer == NULL || callback == NULL) return -1;

    int count = 0;
    for (uint32_t i = 0; i < buffer->capacity; i++)
    {
        buffer_slot_t *slot = &buffer->slots[i];
        uint32_t state = atomic_load_explicit(&slot->state, memory_order_acquire);

        if (state == BUFFER_SLOT_OCCUPIED)
        {
            void *data = atomic_load_explicit(&slot->data, memory_order_acquire);
            callback(i, data, ctx);
            count++;
        }
    }

    return count;
}

int buffer_get_generation(buffer_t *buffer, uint32_t id, uint64_t *generation)
{
    if (buffer == NULL || generation == NULL) return -1;
    if (id >= buffer->capacity) return -1;

    *generation = atomic_load_explicit(&buffer->slots[id].generation, memory_order_acquire);
    return 0;
}

int buffer_validate(buffer_t *buffer, uint32_t id, uint64_t expected_generation)
{
    if (buffer == NULL) return -1;
    if (id >= buffer->capacity) return 0;

    buffer_slot_t *slot = &buffer->slots[id];
    uint32_t state = atomic_load_explicit(&slot->state, memory_order_acquire);

    if (state != BUFFER_SLOT_OCCUPIED) return 0;

    if (expected_generation != 0)
    {
        uint64_t current_gen = atomic_load_explicit(&slot->generation, memory_order_acquire);
        if (current_gen != expected_generation) return 0;
    }

    return 1;
}