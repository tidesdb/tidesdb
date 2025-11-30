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
#ifndef __BUFFER_H__
#define __BUFFER_H__

#include "compat.h"

/* forward declarations */
typedef struct buffer_t buffer_t;
typedef struct buffer_slot_t buffer_slot_t;

/* slot state values */
#define BUFFER_SLOT_FREE      0 /* slot is available */
#define BUFFER_SLOT_ACQUIRED  1 /* slot is being set up */
#define BUFFER_SLOT_OCCUPIED  2 /* slot contains valid data */
#define BUFFER_SLOT_RELEASING 3 /* slot is being released */

/* special ID value indicating invalid/no slot */
#define BUFFER_INVALID_ID ((uint32_t)-1)

/* default retry parameters */
#define BUFFER_DEFAULT_MAX_RETRIES 1000
#define BUFFER_DEFAULT_BACKOFF_US  1

/**
 * buffer_eviction_fn
 * callback function called when a slot is evicted or released
 * @param data pointer to the data being evicted
 * @param ctx user context pointer
 */
typedef void (*buffer_eviction_fn)(void *data, void *ctx);

/**
 * buffer_slot_t
 * a single slot in the buffer
 * @param state atomic state (FREE, ACQUIRED, OCCUPIED, RELEASING)
 * @param generation generation counter for ABA prevention
 * @param data pointer to user data
 */
struct buffer_slot_t
{
    _Atomic(uint32_t) state;
    _Atomic(uint64_t) generation;
    _Atomic(void *) data;
};

/**
 * buffer_t
 * main buffer structure
 * @param capacity maximum number of slots
 * @param slots array of slots
 * @param hint_index hint for next free slot search (reduces contention)
 * @param active_count number of currently occupied slots
 * @param eviction_fn callback for eviction/release
 * @param eviction_ctx context for eviction callback
 * @param max_retries maximum retry attempts for acquire
 * @param backoff_us microseconds to back off between retries
 */
struct buffer_t
{
    uint32_t capacity;
    buffer_slot_t *slots;
    _Atomic(uint32_t) hint_index;
    _Atomic(uint32_t) active_count;
    buffer_eviction_fn eviction_fn;
    void *eviction_ctx;
    uint32_t max_retries;
    uint32_t backoff_us;
};

/**
 * buffer_new
 * creates a new buffer with specified capacity
 * @param buffer pointer to buffer pointer
 * @param capacity number of slots
 * @return 0 on success, -1 on failure
 */
int buffer_new(buffer_t **buffer, uint32_t capacity);

/**
 * buffer_new_with_eviction
 * creates a new buffer with eviction callback
 * @param buffer pointer to buffer pointer
 * @param capacity number of slots
 * @param eviction_fn callback for eviction
 * @param eviction_ctx context for callback
 * @return 0 on success, -1 on failure
 */
int buffer_new_with_eviction(buffer_t **buffer, uint32_t capacity, buffer_eviction_fn eviction_fn,
                             void *eviction_ctx);

/**
 * buffer_set_retry_params
 * sets retry parameters for acquire operations
 * @param buffer buffer
 * @param max_retries maximum retry attempts (0 = unlimited)
 * @param backoff_us microseconds between retries
 * @return 0 on success, -1 on failure
 */
int buffer_set_retry_params(buffer_t *buffer, uint32_t max_retries, uint32_t backoff_us);

/**
 * buffer_acquire
 * acquires a free slot and stores data, returning slot ID
 * uses retry with backoff if no slots available
 * @param buffer buffer
 * @param data pointer to store
 * @param id output slot ID
 * @return 0 on success, -1 on failure (no slots after max retries)
 */
int buffer_acquire(buffer_t *buffer, void *data, uint32_t *id);

/**
 * buffer_try_acquire
 * tries to acquire a slot without retrying
 * @param buffer buffer
 * @param data pointer to store
 * @param id output slot ID
 * @return 0 on success, -1 if no free slots
 */
int buffer_try_acquire(buffer_t *buffer, void *data, uint32_t *id);

/**
 * buffer_get
 * retrieves data from a slot by ID
 * @param buffer buffer
 * @param id slot ID
 * @param data output data pointer
 * @return 0 on success, -1 on failure (invalid ID or slot not occupied)
 */
int buffer_get(buffer_t *buffer, uint32_t id, void **data);

/**
 * buffer_release
 * releases a slot, making it available for reuse
 * calls eviction callback if set
 * @param buffer buffer
 * @param id slot ID
 * @return 0 on success, -1 on failure
 */
int buffer_release(buffer_t *buffer, uint32_t id);

/**
 * buffer_release_silent
 * releases a slot without calling eviction callback
 * @param buffer buffer
 * @param id slot ID
 * @return 0 on success, -1 on failure
 */
int buffer_release_silent(buffer_t *buffer, uint32_t id);

/**
 * buffer_is_occupied
 * checks if a slot is occupied
 * @param buffer buffer
 * @param id slot ID
 * @return 1 if occupied, 0 if not, -1 on error
 */
int buffer_is_occupied(buffer_t *buffer, uint32_t id);

/**
 * buffer_active_count
 * returns number of currently occupied slots
 * @param buffer buffer
 * @return active count, or -1 on error
 */
int buffer_active_count(buffer_t *buffer);

/**
 * buffer_capacity
 * returns buffer capacity
 * @param buffer buffer
 * @return capacity, or -1 on error
 */
int buffer_capacity(buffer_t *buffer);

/**
 * buffer_clear
 * releases all slots, calling eviction callback for each
 * @param buffer buffer
 * @return 0 on success, -1 on failure
 */
int buffer_clear(buffer_t *buffer);

/**
 * buffer_free
 * frees the buffer and all resources
 * calls eviction callback for any occupied slots
 * @param buffer buffer
 */
void buffer_free(buffer_t *buffer);

/**
 * buffer_foreach
 * iterates over all occupied slots
 * @param buffer buffer
 * @param callback function to call for each occupied slot
 * @param ctx user context
 * @return number of slots visited, or -1 on error
 */
int buffer_foreach(buffer_t *buffer, void (*callback)(uint32_t id, void *data, void *ctx),
                   void *ctx);

/**
 * buffer_get_generation
 * gets the generation counter for a slot (for ABA detection)
 * @param buffer buffer
 * @param id slot ID
 * @param generation output generation
 * @return 0 on success, -1 on failure
 */
int buffer_get_generation(buffer_t *buffer, uint32_t id, uint64_t *generation);

/**
 * buffer_validate
 * validates slot ID and optionally checks generation
 * @param buffer buffer
 * @param id slot ID
 * @param expected_generation expected generation (0 to skip check)
 * @return 1 if valid, 0 if invalid, -1 on error
 */
int buffer_validate(buffer_t *buffer, uint32_t id, uint64_t expected_generation);

#endif /* __BUFFER_H__ */