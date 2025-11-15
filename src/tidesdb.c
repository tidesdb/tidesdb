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

/* disable format-truncation warnings. all path buffers use TDB_MAX_PATH_LENGTH (1024) */
#ifndef _MSC_VER
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
#endif

#include "tidesdb.h"

/*
 * serialize_kv_header
 * serializes a key-value header to a buffer
 * @param buf buffer to store serialized header
 * @param version format version
 * @param flags bit flags (bit 0 tombstone/deleted)
 * @param key_size size of key in bytes
 * @param value_size size of value in bytes
 * @param ttl time-to-live (expiration time)
 */
static inline void serialize_kv_header(uint8_t *buf, uint8_t version, uint8_t flags,
                                       uint32_t key_size, uint32_t value_size, int64_t ttl)
{
    buf[0] = version;
    buf[1] = flags;
    encode_uint32_le(buf + 2, key_size);
    encode_uint32_le(buf + 6, value_size);
    encode_int64_le(buf + 10, ttl);
}

/*
 * deserialize_kv_header
 * deserializes a key-value header from a buffer
 * @param buf buffer containing serialized header
 * @param version format version
 * @param flags bit flags (bit 0 tombstone/deleted)
 * @param key_size size of key in bytes
 * @param value_size size of value in bytes
 * @param ttl time-to-live (expiration time)
 */
static inline void deserialize_kv_header(const uint8_t *buf, uint8_t *version, uint8_t *flags,
                                         uint32_t *key_size, uint32_t *value_size, int64_t *ttl)
{
    *version = buf[0];
    *flags = buf[1];
    *key_size = decode_uint32_le(buf + 2);
    *value_size = decode_uint32_le(buf + 6);
    *ttl = decode_int64_le(buf + 10);
}

/* global debug logging flag */
int _tidesdb_debug_enabled = 0;

/*
 * comparator_entry_t
 * @param name comparator name
 * @param compare_fn comparator function
 */
typedef struct
{
    char name[TDB_MAX_COMPARATOR_NAME];
    skip_list_comparator_fn compare_fn;
} comparator_entry_t;

static comparator_entry_t comparator_registry[TDB_MAX_COMPARATORS];
static int num_comparators = 0;
static pthread_mutex_t registry_lock = PTHREAD_MUTEX_INITIALIZER;

/* register built-in comparators automatically */
#ifdef _MSC_VER
static void init_builtin_comparators(void)
{
    tidesdb_register_comparator("memcmp", skip_list_comparator_memcmp);
    tidesdb_register_comparator("string", skip_list_comparator_string);
    tidesdb_register_comparator("numeric", skip_list_comparator_numeric);
}

#pragma section(".CRT$XCU", read)
__declspec(allocate(".CRT$XCU")) void (*init_builtin_comparators_ptr)(void) =
    init_builtin_comparators;
#else
static void __attribute__((constructor)) init_builtin_comparators(void)
{
    tidesdb_register_comparator("memcmp", skip_list_comparator_memcmp);
    tidesdb_register_comparator("string", skip_list_comparator_string);
    tidesdb_register_comparator("numeric", skip_list_comparator_numeric);
}
#endif

int tidesdb_register_comparator(const char *name, skip_list_comparator_fn compare_fn)
{
    if (!name || !compare_fn) return TDB_ERR_INVALID_ARGS;

    pthread_mutex_lock(&registry_lock);

    for (int i = 0; i < num_comparators; i++)
    {
        if (strcmp(comparator_registry[i].name, name) == 0)
        {
            comparator_registry[i].compare_fn = compare_fn;
            pthread_mutex_unlock(&registry_lock);
            return 0;
        }
    }

    if (num_comparators >= TDB_MAX_COMPARATORS)
    {
        pthread_mutex_unlock(&registry_lock);
        return TDB_ERR_MAX_COMPARATORS;
    }

    strncpy(comparator_registry[num_comparators].name, name, TDB_MAX_COMPARATOR_NAME - 1);
    comparator_registry[num_comparators].name[TDB_MAX_COMPARATOR_NAME - 1] = '\0';
    comparator_registry[num_comparators].compare_fn = compare_fn;
    num_comparators++;

    pthread_mutex_unlock(&registry_lock);
    return 0;
}

skip_list_comparator_fn tidesdb_get_comparator(const char *name)
{
    if (!name) return skip_list_comparator_memcmp;

    pthread_mutex_lock(&registry_lock);

    for (int i = 0; i < num_comparators; i++)
    {
        if (strcmp(comparator_registry[i].name, name) == 0)
        {
            skip_list_comparator_fn fn = comparator_registry[i].compare_fn;
            pthread_mutex_unlock(&registry_lock);
            return fn;
        }
    }

    pthread_mutex_unlock(&registry_lock);
    return NULL;
}

/*
 * get_cf_path
 * gets the path to a column family directory
 * @param db tidesdb instance
 * @param cf_name column family name
 * @param path buffer to store path
 */
static void get_cf_path(const tidesdb_t *db, const char *cf_name, char *path);

/*
 * tidesdb_load_sstable
 * loads an sstable from disk
 * @param cf column family
 * @param sstable_id sstable identifier
 * @param sstable pointer to store loaded sstable
 * @return 0 on success, -1 on failure
 */
static int tidesdb_load_sstable(tidesdb_column_family_t *cf, uint64_t sstable_id,
                                tidesdb_sstable_t **sstable);

/*
 * tidesdb_sstable_free
 * frees an sstable
 * @param sstable sstable to free
 */
static void tidesdb_sstable_free(tidesdb_sstable_t *sstable);

/*
 * tidesdb_check_and_flush
 * checks if memtable needs to be flushed
 * @param cf column family
 * @return 0 on success, -1 on failure
 */
static int tidesdb_check_and_flush(tidesdb_column_family_t *cf);

/*
 * tidesdb_memtable_new
 * creates a new memtable
 * @param cf column family
 * @return pointer to new memtable, NULL on failure
 */
static tidesdb_memtable_t *tidesdb_memtable_new(tidesdb_column_family_t *cf);

/*
 * tidesdb_memtable_free
 * frees a memtable
 * @param mt memtable to free
 */
static void tidesdb_memtable_free(tidesdb_memtable_t *mt);

/*
 * tidesdb_memtable_acquire
 * acquires a reference to a memtable
 * @param mt memtable
 */
static inline void tidesdb_memtable_acquire(tidesdb_memtable_t *mt);

/*
 * tidesdb_memtable_release
 * releases a reference to a memtable
 * @param mt memtable
 * @return new reference count
 */
static inline int tidesdb_memtable_release(tidesdb_memtable_t *mt);

/*
 * tidesdb_rotate_memtable
 * rotates the memtable
 * @param cf column family
 * @return 0 on success, -1 on failure
 */
static int tidesdb_rotate_memtable(tidesdb_column_family_t *cf);

/*
 * tidesdb_flush_memtable_to_sstable
 * flushes the memtable to an sstable
 * @param cf column family
 * @param mt memtable to flush
 * @return 0 on success, -1 on failure
 */
static int tidesdb_flush_memtable_to_sstable(tidesdb_column_family_t *cf, tidesdb_memtable_t *mt);

/*
 * compare_keys_with_cf
 * compares two keys using the column family's comparator
 * @param cf column family
 * @param key1 first key
 * @param key1_size size of first key
 * @param key2 second key
 * @param key2_size size of second key
 * @return negative if key1 < key2, zero if equal, positive if key1 > key2
 */
static int compare_keys_with_cf(tidesdb_column_family_t *cf, const uint8_t *key1, size_t key1_size,
                                const uint8_t *key2, size_t key2_size);

/*
 * parse_block
 * parses a block from the block manager
 * @param block block to parse
 * @param cf column family
 * @param key pointer to store parsed key
 * @param key_size pointer to store parsed key size
 * @param value pointer to store parsed value
 * @param value_size pointer to store parsed value size
 * @param deleted pointer to store deleted flag
 * @param ttl pointer to store TTL
 * @return 0 on success, -1 on failure
 */
static int parse_block(block_manager_block_t *block, tidesdb_column_family_t *cf, uint8_t **key,
                       size_t *key_size, uint8_t **value, size_t *value_size, uint8_t *deleted,
                       time_t *ttl);

/*
 * get_sstable_path
 * gets the path to an sstable
 * @param cf column family
 * @param sstable_id sstable identifier
 * @param path buffer to store path
 */
static void get_sstable_path(const tidesdb_column_family_t *cf, uint64_t sstable_id, char *path);

/*
 * peek_next_block_for_merge
 * helper function to read and extract key from next block during compaction merge
 * @param cursor block manager cursor
 * @param blocks_read pointer to blocks read counter
 * @param max_blocks maximum blocks to read
 * @param peek_block pointer to store peeked block
 * @param peek_key pointer to store key pointer
 * @param peek_key_size pointer to store key size
 * @param decompressed_ptr pointer to store decompressed data for cleanup
 * @param cf column family (for compression config)
 * @return 1 if block was read, 0 otherwise
 */
static int peek_next_block_for_merge(block_manager_cursor_t *cursor, int *blocks_read,
                                     int max_blocks, block_manager_block_t **peek_block,
                                     uint8_t **peek_key, size_t *peek_key_size,
                                     uint8_t **decompressed_ptr, tidesdb_column_family_t *cf);

/*
 * tidesdb_validate_kv_size
 * validates that key and value sizes are within memory limits
 * @param db tidesdb instance
 * @param key_size size of key
 * @param value_size size of value
 * @return 0 on success, TDB_ERR_MEMORY_LIMIT if sizes exceed limits
 */
static int tidesdb_validate_kv_size(const tidesdb_t *db, size_t key_size, size_t value_size);

/*
 * tidesdb_build_sstable_index
 * builds a succinct trie index for an existing sstable by reading it sequentially
 * @param sst sstable to build index for
 * @param cf column family
 * @return 0 on success, -1 on failure
 */
static int tidesdb_build_sstable_index(tidesdb_sstable_t *sst, tidesdb_column_family_t *cf);

/*
 * thread_pool_task_t
 * @param type task type (flush or compaction)
 * @param cf column family
 * @param memtable memtable (for flush tasks)
 */
typedef enum
{
    TASK_FLUSH,
    TASK_COMPACTION
} task_type_t;

/*
 * thread_pool_task_t
 * @param type task type (flush or compaction)
 * @param cf column family
 * @param memtable memtable (for flush tasks)
 */
typedef struct
{
    task_type_t type;
    tidesdb_column_family_t *cf;
    tidesdb_memtable_t *memtable;
} thread_pool_task_t;

/*
 * tidesdb_thread_pool_t
 * @param threads array of threads
 * @param num_threads number of threads
 * @param task_queue queue of tasks
 * @param shutdown shutdown flag
 * @param lock mutex lock
 */
struct tidesdb_thread_pool_t
{
    pthread_t *threads;
    int num_threads;
    queue_t *task_queue;
    _Atomic(int) shutdown;
    pthread_mutex_t lock;
};

/*
 * thread_pool_worker
 * worker thread for thread pool
 * @param arg thread pool
 */
static void *thread_pool_worker(void *arg)
{
    tidesdb_thread_pool_t *pool = (tidesdb_thread_pool_t *)arg;

    while (!atomic_load(&pool->shutdown))
    {
        thread_pool_task_t *task = (thread_pool_task_t *)queue_dequeue_wait(pool->task_queue);

        if (atomic_load(&pool->shutdown))
        {
            if (task) free(task);
            break;
        }

        if (!task) continue;

        /* check if column family is being dropped before executing task */
        if (atomic_load(&task->cf->is_dropping))
        {
            /* column family is being dropped, skip task and cleanup */
            if (task->type == TASK_FLUSH && task->memtable)
            {
                tidesdb_memtable_free(task->memtable);
            }
            free(task);
            continue;
        }

        if (task->type == TASK_FLUSH && task->memtable)
        {
            /* check is_dropping BEFORE incrementing to avoid race */
            if (atomic_load(&task->cf->is_dropping))
            {
                tidesdb_memtable_free(task->memtable);
                free(task);
                continue;
            }

            /* increment active operations counter */
            atomic_fetch_add(&task->cf->active_operations, 1);

            /* double-check is_dropping after incrementing */
            if (atomic_load(&task->cf->is_dropping))
            {
                atomic_fetch_sub(&task->cf->active_operations, 1);
                tidesdb_memtable_free(task->memtable);
                free(task);
                continue;
            }

            int flush_result = tidesdb_flush_memtable_to_sstable(task->cf, task->memtable);

            if (flush_result != 0)
            {
                TDB_DEBUG_LOG("Flush failed for column family: %s (memtable id: " TDB_U64_FMT
                              "), memtable remains in immutable queue",
                              task->cf->name, (unsigned long long)task->memtable->id);
            }

            /* decrement active operations counter */
            atomic_fetch_sub(&task->cf->active_operations, 1);

            /* release the task reference BEFORE cleanup */
            tidesdb_memtable_free(task->memtable);

            /* now try cleanup if flush succeeded */
            if (flush_result == 0)
            {
                TDB_DEBUG_LOG("Flush completed, checking for cleanup opportunities");

                /* remove flushed memtables from front of queue if safe */
                /* memtables may finish flushing out of order, so check from the front */
                pthread_mutex_lock(&task->cf->flush_lock);

                size_t queue_size_before = queue_size(task->cf->immutable_memtables);
                TDB_DEBUG_LOG("Queue has %zu immutable memtables before cleanup",
                              queue_size_before);

                int cleaned_count = 0;
                /* keep removing from front while ref_count == 1 (only queue reference) */
                while (1)
                {
                    tidesdb_memtable_t *front_mt =
                        (tidesdb_memtable_t *)queue_peek_at(task->cf->immutable_memtables, 0);
                    if (!front_mt)
                    {
                        TDB_DEBUG_LOG("No more memtables in queue");
                        break;
                    }

                    int current_refs = atomic_load(&front_mt->ref_count);
                    TDB_DEBUG_LOG("Front memtable " TDB_U64_FMT " has ref_count=%d",
                                  (unsigned long long)front_mt->id, current_refs);

                    if (current_refs == 1)
                    {
                        /* only queue holds reference -- safe to remove */
                        tidesdb_memtable_t *dequeued_mt =
                            (tidesdb_memtable_t *)queue_dequeue(task->cf->immutable_memtables);
                        if (dequeued_mt)
                        {
                            cleaned_count++;
                            TDB_DEBUG_LOG("Cleaned up memtable " TDB_U64_FMT " (ref_count was 1)",
                                          (unsigned long long)dequeued_mt->id);
                            tidesdb_memtable_release(dequeued_mt);
                        }
                    }
                    else
                    {
                        /* front memtable still has readers or is being flushed -- stop */
                        TDB_DEBUG_LOG("Stopping cleanup - front memtable has ref_count=%d (>1)",
                                      current_refs);
                        break;
                    }
                }

                size_t remaining = queue_size(task->cf->immutable_memtables);
                pthread_mutex_unlock(&task->cf->flush_lock);

                TDB_DEBUG_LOG("Cleanup complete: cleaned=%d, remaining=%zu", cleaned_count,
                              remaining);
            }

            /* check if compaction is needed */
            int num_ssts = atomic_load(&task->cf->num_sstables);
            if (num_ssts >= 2 && num_ssts >= task->cf->config.max_sstables_before_compaction)
            {
                /* submit compaction task */
                thread_pool_task_t *compact_task = malloc(sizeof(thread_pool_task_t));
                if (compact_task)
                {
                    compact_task->type = TASK_COMPACTION;
                    compact_task->cf = task->cf;
                    compact_task->memtable = NULL;
                    TDB_DEBUG_LOG(
                        "Submitting compaction task for column family: %s (sstables: %d, "
                        "threshold: %d)",
                        task->cf->name, num_ssts, task->cf->config.max_sstables_before_compaction);
                    queue_enqueue(task->cf->db->compaction_pool->task_queue, compact_task);
                }
            }
        }
        else if (task->type == TASK_COMPACTION)
        {
            /* check is_dropping BEFORE incrementing to avoid race */
            if (atomic_load(&task->cf->is_dropping))
            {
                free(task);
                continue;
            }

            /* increment active operations counter */
            atomic_fetch_add(&task->cf->active_operations, 1);

            /* double-check is_dropping after incrementing */
            if (atomic_load(&task->cf->is_dropping))
            {
                atomic_fetch_sub(&task->cf->active_operations, 1);
                free(task);
                continue;
            }

            tidesdb_compact(task->cf);

            /* decrement active operations counter */
            atomic_fetch_sub(&task->cf->active_operations, 1);
        }

        free(task);
    }

    return NULL;
}

/*
 * thread_pool_create
 * creates a thread pool
 * @param num_threads number of threads
 * @return thread pool on success, NULL on failure
 */
static tidesdb_thread_pool_t *thread_pool_create(int num_threads)
{
    if (num_threads <= 0) num_threads = 2;

    tidesdb_thread_pool_t *pool = malloc(sizeof(tidesdb_thread_pool_t));
    if (!pool) return NULL;

    pool->threads = malloc(num_threads * sizeof(pthread_t));
    if (!pool->threads)
    {
        free(pool);
        return NULL;
    }

    pool->task_queue = queue_new();
    if (!pool->task_queue)
    {
        free(pool->threads);
        free(pool);
        return NULL;
    }

    pool->num_threads = num_threads;
    atomic_init(&pool->shutdown, 0);
    pthread_mutex_init(&pool->lock, NULL);

    for (int i = 0; i < num_threads; i++)
    {
        if (pthread_create(&pool->threads[i], NULL, thread_pool_worker, pool) != 0)
        {
            /* cleanup on failure */
            atomic_store(&pool->shutdown, 1);
            for (int j = 0; j < i; j++)
            {
                queue_enqueue(pool->task_queue, NULL);
            }
            for (int j = 0; j < i; j++)
            {
                pthread_join(pool->threads[j], NULL);
            }
            queue_free(pool->task_queue);
            pthread_mutex_destroy(&pool->lock);
            free(pool->threads);
            free(pool);
            return NULL;
        }
    }

    return pool;
}

/*
 * thread_pool_destroy
 * destroys a thread pool
 * @param pool thread pool
 */
static void thread_pool_destroy(tidesdb_thread_pool_t *pool)
{
    if (!pool) return;

    atomic_store(&pool->shutdown, 1);

    /* wake up all threads */
    for (int i = 0; i < pool->num_threads; i++)
    {
        queue_enqueue(pool->task_queue, NULL);
    }

    /* wait for all threads to finish */
    for (int i = 0; i < pool->num_threads; i++)
    {
        pthread_join(pool->threads[i], NULL);
    }

    /* drain remaining tasks */
    thread_pool_task_t *task;
    while ((task = (thread_pool_task_t *)queue_dequeue(pool->task_queue)) != NULL)
    {
        free(task);
    }

    queue_free(pool->task_queue);
    pthread_mutex_destroy(&pool->lock);
    free(pool->threads);
    free(pool);
}

/*
 * thread_pool_submit
 * submits a task to the thread pool
 * @param pool thread pool
 * @param type task type
 * @param cf column family
 * @param memtable memtable
 * @return 0 on success, -1 on failure
 */
static int thread_pool_submit(tidesdb_thread_pool_t *pool, task_type_t type,
                              tidesdb_column_family_t *cf, tidesdb_memtable_t *memtable)
{
    if (!pool || atomic_load(&pool->shutdown)) return -1;

    thread_pool_task_t *task = malloc(sizeof(thread_pool_task_t));
    if (!task) return -1;

    task->type = type;
    task->cf = cf;
    task->memtable = memtable;

    queue_enqueue(pool->task_queue, task);
    return 0;
}

/*
 * tidesdb_sstable_acquire
 * acquires a reference to an sstable
 * @param sst sstable
 */
static inline void tidesdb_sstable_acquire(tidesdb_sstable_t *sst)
{
    if (sst)
    {
        atomic_fetch_add(&sst->ref_count, 1);
    }
}

/*
 * tidesdb_sstable_release
 * releases a reference to an sstable
 * @param sst sstable
 */
static inline int tidesdb_sstable_release(tidesdb_sstable_t *sst)
{
    if (!sst) return 0;

    int old_count = atomic_fetch_sub(&sst->ref_count, 1);
    int new_count = old_count - 1;

    if (new_count == 0)
    {
        tidesdb_sstable_free(sst);
    }

    return new_count;
}

/*
 * tidesdb_memtable_acquire
 * acquires a reference to a memtable
 * @param mt memtable
 */
static inline void tidesdb_memtable_acquire(tidesdb_memtable_t *mt)
{
    if (mt)
    {
        atomic_fetch_add(&mt->ref_count, 1);
    }
}

/*
 * heap_swap
 * swaps two entries in the heap
 * @param heap heap array
 * @param i index of first entry
 * @param j index of second entry
 */
static void heap_swap(tidesdb_iter_entry_t *heap, int i, int j)
{
    tidesdb_iter_entry_t temp = heap[i];
    heap[i] = heap[j];
    heap[j] = temp;
}

/*
 * heap_sift_down
 * sifts an entry down the heap
 * @param iter iterator
 * @param idx index of entry to sift
 */
static void heap_sift_down(tidesdb_iter_t *iter, int idx)
{
    int size = iter->heap_size;
    int forward = (iter->direction > 0);

    while (idx < size)
    {
        int best = idx;
        int left = 2 * idx + 1;
        int right = 2 * idx + 2;

        if (left < size)
        {
            const uint8_t *left_key = iter->heap[left].key;
            const uint8_t *best_key = iter->heap[best].key;
            size_t left_size = iter->heap[left].key_size;
            size_t best_size = iter->heap[best].key_size;
            size_t min_size = (left_size < best_size) ? left_size : best_size;
            int cmp = memcmp(left_key, best_key, min_size);
            if (cmp == 0) cmp = (left_size < best_size) ? -1 : (left_size > best_size) ? 1 : 0;
            if (forward ? (cmp < 0) : (cmp > 0)) best = left;
        }

        if (right < size)
        {
            const uint8_t *right_key = iter->heap[right].key;
            const uint8_t *best_key = iter->heap[best].key;
            size_t right_size = iter->heap[right].key_size;
            size_t best_size = iter->heap[best].key_size;
            size_t min_size = (right_size < best_size) ? right_size : best_size;
            int cmp = memcmp(right_key, best_key, min_size);
            if (cmp == 0) cmp = (right_size < best_size) ? -1 : (right_size > best_size) ? 1 : 0;
            if (forward ? (cmp < 0) : (cmp > 0)) best = right;
        }

        if (best == idx) break;

        heap_swap(iter->heap, idx, best);
        idx = best;
    }
}

/*
 * heap_sift_up
 * sifts an entry up the heap
 * @param iter iterator
 * @param idx index of entry to sift
 */
static void heap_sift_up(tidesdb_iter_t *iter, int idx)
{
    int forward = (iter->direction > 0);

    while (idx > 0)
    {
        int parent = (idx - 1) / 2;
        const uint8_t *idx_key = iter->heap[idx].key;
        const uint8_t *parent_key = iter->heap[parent].key;
        size_t idx_size = iter->heap[idx].key_size;
        size_t parent_size = iter->heap[parent].key_size;
        size_t min_size = (idx_size < parent_size) ? idx_size : parent_size;
        int cmp = memcmp(idx_key, parent_key, min_size);
        if (cmp == 0) cmp = (idx_size < parent_size) ? -1 : (idx_size > parent_size) ? 1 : 0;
        if (forward ? (cmp >= 0) : (cmp <= 0)) break;

        heap_swap(iter->heap, idx, parent);
        idx = parent;
    }
}

/*
 * heap_push
 * pushes an entry into the heap
 * @param iter iterator
 * @param entry entry to push
 * @return 0 on success, -1 on failure
 */
static int heap_push(tidesdb_iter_t *iter, tidesdb_iter_entry_t *entry)
{
    if (iter->heap_size >= iter->heap_capacity)
    {
        int new_cap = iter->heap_capacity == 0 ? 16 : iter->heap_capacity * 2;
        tidesdb_iter_entry_t *new_heap =
            realloc(iter->heap, new_cap * sizeof(tidesdb_iter_entry_t));
        if (!new_heap) return -1;
        iter->heap = new_heap;
        iter->heap_capacity = new_cap;
    }

    iter->heap[iter->heap_size] = *entry;
    heap_sift_up(iter, iter->heap_size);
    iter->heap_size++;
    return 0;
}

/*
 * heap_pop
 * pops an entry from the heap
 * @param iter iterator
 * @param entry buffer to store entry
 * @return 0 on success, -1 on failure
 */
static int heap_pop(tidesdb_iter_t *iter, tidesdb_iter_entry_t *entry)
{
    if (iter->heap_size == 0) return -1;

    *entry = iter->heap[0];
    iter->heap_size--;

    if (iter->heap_size > 0)
    {
        iter->heap[0] = iter->heap[iter->heap_size];
        heap_sift_down(iter, 0);
    }

    return 0;
}

/*
 * iter_refill_from_memtable
 * refills iterator from active memtable
 * @param iter iterator
 * @return 0 on success, -1 on failure
 */
static int iter_refill_from_memtable(tidesdb_iter_t *iter)
{
    if (!iter->memtable_cursor) return 0;

    while (skip_list_cursor_has_next(iter->memtable_cursor))
    {
        if (skip_list_cursor_next(iter->memtable_cursor) != 0) break;

        uint8_t *k = NULL, *v = NULL;
        size_t k_size = 0, v_size = 0;
        time_t ttl = 0;
        uint8_t deleted = 0;

        if (skip_list_cursor_get(iter->memtable_cursor, &k, &k_size, &v, &v_size, &ttl, &deleted) !=
            0)
            break;

        if (ttl > 0 && time(NULL) > ttl) continue;
        if (deleted) continue;

        uint8_t *entry_key = malloc(k_size);
        uint8_t *entry_value = v_size > 0 ? malloc(v_size) : NULL;

        if (!entry_key || (v_size > 0 && !entry_value))
        {
            if (entry_key) free(entry_key);
            if (entry_value) free(entry_value);
            return -1;
        }

        memcpy(entry_key, k, k_size);
        if (v_size > 0) memcpy(entry_value, v, v_size);

        tidesdb_iter_entry_t entry = {.key = entry_key,
                                      .key_size = k_size,
                                      .value = entry_value,
                                      .value_size = v_size,
                                      .deleted = deleted,
                                      .ttl = ttl,
                                      .source_type = 0,
                                      .source_index = 0};

        return heap_push(iter, &entry);
    }
    return 0;
}

/*
 * iter_refill_from_immutable
 * refills iterator from immutable memtable
 * @param iter iterator
 * @param idx immutable memtable index
 * @return 0 on success, -1 on failure
 */
static int iter_refill_from_immutable(tidesdb_iter_t *iter, int idx)
{
    if (idx >= iter->num_immutable_cursors || !iter->immutable_memtable_cursors[idx]) return 0;

    while (skip_list_cursor_has_next(iter->immutable_memtable_cursors[idx]))
    {
        if (skip_list_cursor_next(iter->immutable_memtable_cursors[idx]) != 0) break;

        uint8_t *k = NULL, *v = NULL;
        size_t k_size = 0, v_size = 0;
        time_t ttl = 0;
        uint8_t deleted = 0;

        if (skip_list_cursor_get(iter->immutable_memtable_cursors[idx], &k, &k_size, &v, &v_size,
                                 &ttl, &deleted) != 0)
            break;

        if (ttl > 0 && time(NULL) > ttl) continue;
        if (deleted) continue;

        tidesdb_iter_entry_t entry = {.key = malloc(k_size),
                                      .key_size = k_size,
                                      .value = v_size > 0 ? malloc(v_size) : NULL,
                                      .value_size = v_size,
                                      .deleted = deleted,
                                      .ttl = ttl,
                                      .source_type = 1,
                                      .source_index = idx};

        if (entry.key && (v_size == 0 || entry.value))
        {
            memcpy(entry.key, k, k_size);
            if (v_size > 0 && entry.value)
            {
                memcpy(entry.value, v, v_size);
            }
            return heap_push(iter, &entry);
        }
        if (entry.key) free(entry.key);
        if (entry.value) free(entry.value);
        return -1;
    }
    return 0;
}

/*
 * iter_refill_from_sstable
 * refills iterator from sstable
 * @param iter iterator
 * @param idx sstable index
 * @return 0 on success, -1 on failure
 */
static int iter_refill_from_sstable(tidesdb_iter_t *iter, int idx)
{
    if (idx >= iter->num_sstable_cursors || !iter->sstable_cursors[idx]) return 0;

    /* stop reading after num_entries to avoid reading metadata blocks */
    tidesdb_sstable_t *sst = iter->sstables[idx];
    int num_entries = atomic_load(&sst->num_entries);
    /* skip boundary check if blocks_read is -1 (positioned via block index) */
    if (iter->sstable_blocks_read[idx] >= num_entries && iter->sstable_blocks_read[idx] != -1)
        return 0;

    while (block_manager_cursor_has_next(iter->sstable_cursors[idx]))
    {
        /* check BEFORE positioning to prevent reading past num_entries */
        /* skip check if blocks_read is -1 (positioned via block index) */
        if (iter->sstable_blocks_read[idx] >= num_entries && iter->sstable_blocks_read[idx] != -1)
            break;

        /* position at first block or advance to next */
        if (iter->sstable_blocks_read[idx] == 0)
        {
            /* first read, position at first block */
            if (iter->sstable_cursors[idx]->current_pos == BLOCK_MANAGER_HEADER_SIZE)
            {
                if (block_manager_cursor_goto_first(iter->sstable_cursors[idx]) != 0) break;
            }
        }
        else
        {
            if (block_manager_cursor_next(iter->sstable_cursors[idx]) != 0) break;
        }

        /* increment blocks_read */
        iter->sstable_blocks_read[idx]++;

        /* ensure we don't read beyond num_entries */
        if (iter->sstable_blocks_read[idx] > num_entries)
        {
            break;
        }

        block_manager_block_t *block = block_manager_cursor_read(iter->sstable_cursors[idx]);
        if (!block) break;

        uint8_t *k = NULL, *v = NULL;
        size_t k_size = 0, v_size = 0;
        uint8_t deleted = 0;
        time_t ttl = 0;

        int parse_result = parse_block(block, iter->cf, &k, &k_size, &v, &v_size, &deleted, &ttl);
        block_manager_block_free(block);

        if (parse_result != 0) break;

        if (ttl > 0 && time(NULL) > ttl)
        {
            free(k);
            free(v);
            continue;
        }

        if (deleted)
        {
            free(k);
            free(v);
            continue;
        }

        tidesdb_iter_entry_t entry = {.key = k,
                                      .key_size = k_size,
                                      .value = v,
                                      .value_size = v_size,
                                      .deleted = deleted,
                                      .ttl = ttl,
                                      .source_type = 2,
                                      .source_index = idx};

        return heap_push(iter, &entry);
    }
    return 0;
}

/*
 * iter_refill_from_memtable_backward
 * refills iterator from active memtable backward
 * @param iter iterator
 * @return 0 on success, -1 on failure
 */
static int iter_refill_from_memtable_backward(tidesdb_iter_t *iter)
{
    if (!iter->memtable_cursor) return 0;

    /* check if we're at a valid position (not header) */
    if (iter->memtable_cursor->current &&
        iter->memtable_cursor->current != iter->memtable_cursor->list->header)
    {
        /* we're at a valid node, read it first */
        uint8_t *k = NULL, *v = NULL;
        size_t k_size = 0, v_size = 0;
        time_t ttl = 0;
        uint8_t deleted = 0;

        if (skip_list_cursor_get(iter->memtable_cursor, &k, &k_size, &v, &v_size, &ttl, &deleted) ==
            0)
        {
            if (ttl > 0 && time(NULL) > ttl)
            {
                skip_list_cursor_prev(iter->memtable_cursor);
                return 0;
            }

            if (deleted)
            {
                skip_list_cursor_prev(iter->memtable_cursor);
                return 0;
            }

            tidesdb_iter_entry_t entry = {.key = malloc(k_size),
                                          .key_size = k_size,
                                          .value = v_size > 0 ? malloc(v_size) : NULL,
                                          .value_size = v_size,
                                          .deleted = deleted,
                                          .ttl = ttl,
                                          .source_type = 0,
                                          .source_index = 0};

            if (entry.key && (v_size == 0 || entry.value))
            {
                memcpy(entry.key, k, k_size);
                if (v_size > 0 && entry.value)
                {
                    memcpy(entry.value, v, v_size);
                }
                /* move backward for next call */
                skip_list_node_t *old_pos = iter->memtable_cursor->current;
                skip_list_cursor_prev(iter->memtable_cursor);

                /* if cursor didn't move, we're at the beginning; mark as exhausted */
                if (iter->memtable_cursor->current == old_pos)
                {
                    if (iter->memtable_cursor->current)
                        skip_list_release_node(iter->memtable_cursor->current);
                    iter->memtable_cursor->current = NULL;
                }
                return heap_push(iter, &entry);
            }
            if (entry.key) free(entry.key);
            if (entry.value) free(entry.value);
            return -1;
        }
    }
    return 0;
}

/*
 * iter_refill_from_immutable_backward
 * refills iterator from immutable memtable backward
 * @param iter iterator
 * @param idx immutable memtable index
 * @return 0 on success, -1 on failure
 */
static int iter_refill_from_immutable_backward(tidesdb_iter_t *iter, int idx)
{
    if (idx >= iter->num_immutable_cursors || !iter->immutable_memtable_cursors[idx]) return 0;

    /* check if we're at a valid position (not header) */
    if (iter->immutable_memtable_cursors[idx]->current &&
        iter->immutable_memtable_cursors[idx]->current !=
            iter->immutable_memtable_cursors[idx]->list->header)
    {
        /* we're at a valid node, read it first */
        uint8_t *k = NULL, *v = NULL;
        size_t k_size = 0, v_size = 0;
        time_t ttl = 0;
        uint8_t deleted = 0;

        if (skip_list_cursor_get(iter->immutable_memtable_cursors[idx], &k, &k_size, &v, &v_size,
                                 &ttl, &deleted) == 0)
        {
            if (ttl > 0 && time(NULL) > ttl)
            {
                /* skip expired, move backward and return */
                skip_list_cursor_prev(iter->immutable_memtable_cursors[idx]);
                return 0;
            }

            if (deleted)
            {
                /* skip tombstones, move backward and return */
                skip_list_cursor_prev(iter->immutable_memtable_cursors[idx]);
                return 0;
            }

            tidesdb_iter_entry_t entry = {.key = malloc(k_size),
                                          .key_size = k_size,
                                          .value = v_size > 0 ? malloc(v_size) : NULL,
                                          .value_size = v_size,
                                          .deleted = deleted,
                                          .ttl = ttl,
                                          .source_type = 1,
                                          .source_index = idx};

            if (entry.key && (v_size == 0 || entry.value))
            {
                memcpy(entry.key, k, k_size);
                if (v_size > 0 && entry.value)
                {
                    memcpy(entry.value, v, v_size);
                }
                /* move backward for next call */
                skip_list_node_t *old_pos = iter->immutable_memtable_cursors[idx]->current;
                skip_list_cursor_prev(iter->immutable_memtable_cursors[idx]);

                if (iter->immutable_memtable_cursors[idx]->current == old_pos)
                {
                    if (iter->immutable_memtable_cursors[idx]->current)
                        skip_list_release_node(iter->immutable_memtable_cursors[idx]->current);
                    iter->immutable_memtable_cursors[idx]->current = NULL;
                }
                return heap_push(iter, &entry);
            }
            if (entry.key) free(entry.key);
            if (entry.value) free(entry.value);
            return -1;
        }
    }
    return 0;
}

/*
 * iter_refill_from_sstable_backward
 * refills iterator from sstable backward
 * @param iter iterator
 * @param idx sstable index
 * @return 0 on success, -1 on failure
 */
static int iter_refill_from_sstable_backward(tidesdb_iter_t *iter, int idx)
{
    if (idx >= iter->num_sstable_cursors || !iter->sstable_cursors[idx])
    {
        return 0;
    }

    tidesdb_sstable_t *sst = iter->sstables[idx];
    if (sst && iter->sstable_blocks_read[idx] <= 0)
    {
        return 0;
    }

    if (block_manager_cursor_has_prev(iter->sstable_cursors[idx]))
    {
        int num_entries = atomic_load(&sst->num_entries);
        /* position at last block or move to previous */
        if (sst && iter->sstable_blocks_read[idx] == num_entries)
        {
            /* first read after seek_to_last, go to last KV block (0-indexed) */

            if (block_manager_cursor_goto(iter->sstable_cursors[idx],
                                          (uint64_t)(num_entries - 1)) != 0)
            {
                return 0;
            }
            iter->sstable_blocks_read[idx] = num_entries - 1;
        }
        else
        {
            if (block_manager_cursor_prev(iter->sstable_cursors[idx]) != 0) return 0;
            iter->sstable_blocks_read[idx]--;
        }

        block_manager_block_t *block = block_manager_cursor_read(iter->sstable_cursors[idx]);
        if (!block) return 0;

        uint8_t *k = NULL, *v = NULL;
        size_t k_size = 0, v_size = 0;
        uint8_t deleted = 0;
        time_t ttl = 0;

        int parse_result = parse_block(block, iter->cf, &k, &k_size, &v, &v_size, &deleted, &ttl);
        block_manager_block_free(block);

        if (parse_result != 0) return 0;

        if (ttl > 0 && time(NULL) > ttl)
        {
            free(k);
            free(v);
            return 0;
        }

        if (deleted)
        {
            free(k);
            free(v);
            return 0;
        }

        tidesdb_iter_entry_t entry = {.key = k,
                                      .key_size = k_size,
                                      .value = v,
                                      .value_size = v_size,
                                      .deleted = deleted,
                                      .ttl = ttl,
                                      .source_type = 2,
                                      .source_index = idx};

        return heap_push(iter, &entry);
    }
    return 0;
}

/*
 * tidesdb_memtable_release
 * releases a reference to a memtable
 * @param mt memtable to release
 * @return new reference count
 */
static inline int tidesdb_memtable_release(tidesdb_memtable_t *mt)
{
    if (!mt) return 0;

    int old_count = atomic_fetch_sub(&mt->ref_count, 1);
    int new_count = old_count - 1;

    if (old_count == 1)
    {
        int expected = 0;
        if (atomic_compare_exchange_strong(&mt->ref_count, &expected, -1))
        {
            if (mt->memtable) skip_list_free(mt->memtable);
            if (mt->wal) block_manager_close(mt->wal);
            pthread_mutex_destroy(&mt->ref_lock);
            free(mt);
            return 0;
        }
    }

    return new_count > 0 ? new_count : 0;
}

tidesdb_column_family_config_t tidesdb_default_column_family_config(void)
{
    tidesdb_column_family_config_t config = {
        .memtable_flush_size = TDB_DEFAULT_MEMTABLE_FLUSH_SIZE,
        .max_sstables_before_compaction = TDB_DEFAULT_MAX_SSTABLES,
        .compaction_threads = TDB_DEFAULT_COMPACTION_THREADS,
        .sl_max_level = TDB_DEFAULT_SKIPLIST_LEVELS,
        .sl_probability = TDB_DEFAULT_SKIPLIST_PROBABILITY,
        .enable_compression = 1,
        .compression_algorithm = COMPRESS_LZ4,
        .enable_bloom_filter = 1,
        .bloom_filter_fp_rate = TDB_DEFAULT_BLOOM_FILTER_FP_RATE,
        .enable_background_compaction = 1,
        .background_compaction_interval = TDB_DEFAULT_BACKGROUND_COMPACTION_INTERVAL,
        .enable_block_indexes = 1,
        .sync_mode = TDB_SYNC_FULL,
        .comparator_name = {0}};
    return config;
}

/*
 * mkdir_p
 * creates directory if it doesn't exist
 * @param path path to directory
 * @return 0 on success, -1 on failure
 */
static int mkdir_p(const char *path)
{
    struct stat st;
    if (stat(path, &st) == -1)
    {
        if (mkdir(path, 0755) == -1)
        {
            return -1;
        }
    }
    return 0;
}

/*
 * tidesdb_validate_kv_size
 * validates that key and value sizes are within memory limits
 * @param db tidesdb instance
 * @param key_size size of key
 * @param value_size size of value
 * @return 0 on success, TDB_ERR_MEMORY_LIMIT if sizes exceed limits
 */
static int tidesdb_validate_kv_size(const tidesdb_t *db, size_t key_size, size_t value_size)
{
    if (!db) return TDB_ERR_INVALID_ARGS;

    /* check for integer overflow */
    if (key_size > SIZE_MAX - value_size - TDB_KV_HEADER_SIZE)
    {
        TDB_DEBUG_LOG("Key/value size overflow detected");
        return TDB_ERR_MEMORY_LIMIT;
    }

    size_t total_size = key_size + value_size + TDB_KV_HEADER_SIZE;

    size_t max_allowed = (size_t)(db->available_memory * TDB_MEMORY_PERCENTAGE / 100);

    /* ensure minimum of TDB_MIN_KEY_VALUE_SIZE for single key-value pair, even on low-memory
     * systems */
    if (max_allowed < TDB_MIN_KEY_VALUE_SIZE)
    {
        max_allowed = TDB_MIN_KEY_VALUE_SIZE;
    }

    if (total_size > max_allowed)
    {
        TDB_DEBUG_LOG("Key/value size (" TDB_SIZE_FMT " bytes) exceeds memory limit " TDB_SIZE_FMT,
                      TDB_SIZE_CAST(total_size), TDB_SIZE_CAST(max_allowed));
        return TDB_ERR_MEMORY_LIMIT;
    }

    return 0;
}

/*
 * tidesdb_build_sstable_index
 * builds index for sstable
 * @param sst sstable to build index for
 * @param cf column family
 * @return 0 on success, -1 on failure
 */
static int tidesdb_build_sstable_index(tidesdb_sstable_t *sst, tidesdb_column_family_t *cf)
{
    if (!sst || !cf || !sst->block_manager) return -1;
    if (!cf->config.enable_block_indexes) return 0;

    TDB_DEBUG_LOG("Building succinct trie index for SSTable " TDB_U64_FMT " (%d entries)",
                  (unsigned long long)sst->id, sst->num_entries);

    /* use streaming builder for reduced allocation overhead */
    /* sstable keys are already sorted, perfect for streaming mode */
    skip_list_comparator_fn cmp_fn = tidesdb_get_comparator(cf->comparator_name);
    char cf_path[TDB_MAX_PATH_LENGTH];
    get_cf_path(cf->db, cf->name, cf_path);
    succinct_trie_builder_t *builder =
        succinct_trie_builder_new(cf_path, (succinct_trie_comparator_fn)cmp_fn, NULL);
    if (!builder) return -1;

    /* allocate buffer to hold all keys (needed because decompressed blocks are freed immediately)
     */
    size_t keys_buffer_capacity = SUCCINCT_TRIE_INITIAL_BUFFER_SIZE;
    size_t keys_buffer_used = 0;
    uint8_t *keys_buffer = malloc(keys_buffer_capacity);
    if (!keys_buffer)
    {
        succinct_trie_builder_free(builder);
        return -1;
    }

    /* create cursor to iterate through blocks in order */
    block_manager_cursor_t *cursor = NULL;
    if (block_manager_cursor_init(&cursor, sst->block_manager) != 0)
    {
        free(keys_buffer);
        succinct_trie_builder_free(builder);
        return -1;
    }

    if (block_manager_cursor_goto_first(cursor) != 0)
    {
        block_manager_cursor_free(cursor);
        free(keys_buffer);
        succinct_trie_builder_free(builder);
        return -1;
    }

    /* iterate through all blocks and add keys to builder */
    int blocks_read = 0;
    while (blocks_read < sst->num_entries && block_manager_cursor_has_next(cursor))
    {
        /* save current byte offset before reading */
        uint64_t block_offset = cursor->current_pos;
        block_manager_block_t *block = block_manager_cursor_read(cursor);
        if (!block) break;

        uint8_t *data = block->data;
        size_t data_size = block->size;
        uint8_t *decompressed = NULL;

        /* decompress if needed */
        if (cf->config.enable_compression)
        {
            size_t decompressed_size = 0;
            decompressed = decompress_data(data, data_size, &decompressed_size,
                                           cf->config.compression_algorithm);
            if (decompressed)
            {
                data = decompressed;
                data_size = decompressed_size;
            }
        }

        /* parse header and extract key */
        if (data_size >= TDB_KV_HEADER_SIZE)
        {
            uint8_t version, flags;
            uint32_t key_size, value_size;
            int64_t ttl;
            deserialize_kv_header(data, &version, &flags, &key_size, &value_size, &ttl);

            uint8_t *key_src = data + TDB_KV_HEADER_SIZE;

            /* ensure buffer has space for this key */
            if (keys_buffer_used + key_size > keys_buffer_capacity)
            {
                size_t new_capacity = keys_buffer_capacity * 2;
                while (keys_buffer_used + key_size > new_capacity) new_capacity *= 2;
                uint8_t *new_buffer = realloc(keys_buffer, new_capacity);
                if (!new_buffer)
                {
                    if (decompressed) free(decompressed);
                    block_manager_block_free(block);
                    block_manager_cursor_free(cursor);
                    free(keys_buffer);
                    succinct_trie_builder_free(builder);
                    return -1;
                }
                keys_buffer = new_buffer;
                keys_buffer_capacity = new_capacity;
            }

            /* copy key into buffer (needed because decompressed block data is freed immediately) */
            uint8_t *key_ptr = keys_buffer + keys_buffer_used;
            memcpy(key_ptr, key_src, key_size);
            keys_buffer_used += key_size;

            /* store byte offset for O(1) direct positioning */
            succinct_trie_builder_add(builder, key_ptr, key_size, (int64_t)block_offset);
        }

        /* free decompressed data immediately */
        if (decompressed) free(decompressed);
        block_manager_block_free(block);

        blocks_read++;
        if (block_manager_cursor_next(cursor) != 0) break;
    }

    block_manager_cursor_free(cursor);

    /* build the trie (keys_buffer must stay valid until this completes) */
    sst->index = succinct_trie_builder_build(builder);

    /* now safe to free the keys buffer */
    free(keys_buffer);

    if (sst->index)
    {
        TDB_DEBUG_LOG("Succinct trie index built successfully");
    }

    return sst->index ? 0 : -1;
}

/*
 * get_cf_path
 * gets column family directory path
 * @param db tidesdb instance
 * @param cf_name column family name
 * @param path buffer to store path
 */
static void get_cf_path(const tidesdb_t *db, const char *cf_name, char *path)
{
    (void)snprintf(path, TDB_MAX_PATH_LENGTH, "%s" PATH_SEPARATOR "%s", db->config.db_path,
                   cf_name);
}

/*
 * get_sstable_path
 * gets sstable file path
 * @param cf column family
 * @param sstable_id sstable identifier
 * @param path buffer to store path
 */
static void get_sstable_path(const tidesdb_column_family_t *cf, uint64_t sstable_id, char *path)
{
    char cf_path[TDB_MAX_PATH_LENGTH];
    get_cf_path(cf->db, cf->name, cf_path);
    (void)snprintf(path, TDB_MAX_PATH_LENGTH,
                   "%s" PATH_SEPARATOR TDB_SSTABLE_PREFIX TDB_U64_FMT "%s", cf_path,
                   TDB_U64_CAST(sstable_id), TDB_SSTABLE_EXT);
}

/*
 * config_handler
 * INI parser handler for column family config
 */
static int config_handler(void *user, const char *section, const char *name, const char *value)
{
    tidesdb_column_family_config_t *config = (tidesdb_column_family_config_t *)user;

    if (strcmp(section, "column_family") == 0)
    {
        if (strcmp(name, "memtable_flush_size") == 0)
        {
            config->memtable_flush_size = (size_t)strtoull(value, NULL, 10);
        }
        else if (strcmp(name, "max_sstables_before_compaction") == 0)
        {
            config->max_sstables_before_compaction = atoi(value);
        }
        else if (strcmp(name, "compaction_threads") == 0)
        {
            config->compaction_threads = atoi(value);
        }
        else if (strcmp(name, "sl_max_level") == 0)
        {
            config->sl_max_level = atoi(value);
        }
        else if (strcmp(name, "sl_probability") == 0)
        {
            config->sl_probability = (float)atof(value);
        }
        else if (strcmp(name, "enable_compression") == 0)
        {
            config->enable_compression = atoi(value);
        }
        else if (strcmp(name, "compression_algorithm") == 0)
        {
            config->compression_algorithm = atoi(value);
        }
        else if (strcmp(name, "enable_bloom_filter") == 0)
        {
            config->enable_bloom_filter = atoi(value);
        }
        else if (strcmp(name, "bloom_filter_fp_rate") == 0)
        {
            config->bloom_filter_fp_rate = atof(value);
        }
        else if (strcmp(name, "enable_background_compaction") == 0)
        {
            config->enable_background_compaction = atoi(value);
        }
        else if (strcmp(name, "background_compaction_interval") == 0)
        {
            config->background_compaction_interval = atoi(value);
        }
        else if (strcmp(name, "enable_block_indexes") == 0)
        {
            config->enable_block_indexes = atoi(value);
        }
        else if (strcmp(name, "sync_mode") == 0)
        {
            config->sync_mode = (tidesdb_sync_mode_t)atoi(value);
        }
        else if (strcmp(name, "comparator_name") == 0)
        {
            strncpy(config->comparator_name, value, TDB_MAX_COMPARATOR_NAME - 1);
            config->comparator_name[TDB_MAX_COMPARATOR_NAME - 1] = '\0';
        }
        else if (strcmp(name, "block_manager_cache_size") == 0)
        {
            config->block_manager_cache_size = atoi(value);
        }
    }
    return 1;
}

/*
 * get_cf_config_path
 * gets column family config file path
 * @param cf column family
 * @param path buffer to store path
 */
static void get_cf_config_path(const tidesdb_column_family_t *cf, char *path)
{
    char cf_path[TDB_MAX_PATH_LENGTH];
    get_cf_path(cf->db, cf->name, cf_path);
    (void)snprintf(path, TDB_MAX_PATH_LENGTH, "%s" PATH_SEPARATOR TDB_CONFIG_FILE_NAME "%s",
                   cf_path, TDB_COLUMN_FAMILY_CONFIG_FILE_EXT);
}

/*
 * save_cf_config
 * saves column family config to file
 * @param cf column family
 * @return 0 on success, -1 on failure
 */
static int save_cf_config(tidesdb_column_family_t *cf)
{
    char config_path[TDB_MAX_PATH_LENGTH];
    get_cf_config_path(cf, config_path);

    FILE *f = fopen(config_path, "w");
    if (!f) return -1;

    fprintf(f, "[column_family]\n");
    fprintf(f, "memtable_flush_size=%zu\n", cf->config.memtable_flush_size);
    fprintf(f, "max_sstables_before_compaction=%d\n", cf->config.max_sstables_before_compaction);
    fprintf(f, "compaction_threads=%d\n", cf->config.compaction_threads);
    fprintf(f, "sl_max_level=%d\n", cf->config.sl_max_level);
    fprintf(f, "sl_probability=%f\n", cf->config.sl_probability);
    fprintf(f, "enable_compression=%d\n", cf->config.enable_compression);
    fprintf(f, "compression_algorithm=%d\n", cf->config.compression_algorithm);
    fprintf(f, "enable_bloom_filter=%d\n", cf->config.enable_bloom_filter);
    fprintf(f, "bloom_filter_fp_rate=%f\n", cf->config.bloom_filter_fp_rate);
    fprintf(f, "enable_background_compaction=%d\n", cf->config.enable_background_compaction);
    fprintf(f, "background_compaction_interval=%d\n", cf->config.background_compaction_interval);
    fprintf(f, "enable_block_indexes=%d\n", cf->config.enable_block_indexes);
    fprintf(f, "sync_mode=%d\n", cf->config.sync_mode);
    fprintf(f, "comparator_name=%s\n",
            cf->config.comparator_name[0] ? cf->config.comparator_name : "");
    fprintf(f, "block_manager_cache_size=%d\n", cf->config.block_manager_cache_size);

    fclose(f);
    return 0;
}

/*
 * load_cf_config
 * loads column family config from file
 * @param cf column family
 * @return 0 on success, -1 on failure
 */
static int load_cf_config(tidesdb_column_family_t *cf)
{
    char config_path[TDB_MAX_PATH_LENGTH];
    get_cf_config_path(cf, config_path);

    /* parse ini config file */
    if (ini_parse(config_path, config_handler, &cf->config) < 0)
    {
        return -1; /* file doesn't exist or parse error, use defaults */
    }

    return 0;
}

/*
 * block_manager_evict_cb
 * callback for evicting block managers from cache
 * @param key key for block manager
 * @param value block manager
 * @param user_data user data (not used)
 */
static void block_manager_evict_cb(const char *key, void *value, void *user_data)
{
    (void)key;
    (void)user_data;
    block_manager_t *bm = (block_manager_t *)value;
    if (bm)
    {
        TDB_DEBUG_LOG("Evicting block manager from cache: %s", key);
        block_manager_close(bm);
    }
}

/*
 * get_cached_block_manager
 * gets a block manager from the cache
 * @param db tidesdb instance
 * @param path path to block manager
 * @param sync_mode sync mode for block manager
 * @return block manager on success, NULL on failure
 */
static block_manager_t *get_cached_block_manager(tidesdb_t *db, const char *path,
                                                 tidesdb_sync_mode_t sync_mode, uint32_t cache_size)
{
    if (!db || !path || !db->block_manager_cache) return NULL;

    block_manager_t *bm = (block_manager_t *)lru_cache_get(db->block_manager_cache, path);
    if (bm)
    {
        TDB_DEBUG_LOG("Block manager cache hit: %s", path);
        return bm;
    }

    TDB_DEBUG_LOG("Block manager cache miss: %s", path);
    bm = NULL;

    if (block_manager_open_with_cache(&bm, path, convert_sync_mode((int)sync_mode), cache_size) ==
        -1)
    {
        return NULL;
    }

    if (lru_cache_put(db->block_manager_cache, path, bm, block_manager_evict_cb, NULL) == -1)
    {
        block_manager_close(bm);
        return NULL;
    }

    return bm;
}

int tidesdb_open(const tidesdb_config_t *config, tidesdb_t **db)
{
    if (!config || !db) return TDB_ERR_INVALID_ARGS;

    _tidesdb_debug_enabled = config->enable_debug_logging;

    TDB_DEBUG_LOG("Opening TidesDB at path: %s", config->db_path);

    *db = malloc(sizeof(tidesdb_t));
    if (!*db) return TDB_ERR_MEMORY;

    memcpy(&(*db)->config, config, sizeof(tidesdb_config_t));

    /* apply defaults for unset config values */
    if ((*db)->config.wal_recovery_poll_interval_ms <= 0)
    {
        (*db)->config.wal_recovery_poll_interval_ms = TDB_DEFAULT_WAL_RECOVERY_POLL_INTERVAL_MS;
    }
    /* wait_for_wal_recovery is a boolean flag, no default needed (0 = false is valid) */
    (*db)->column_families = NULL;
    (*db)->num_cfs = 0;
    (*db)->cf_capacity = 0;
    (*db)->block_manager_cache = NULL;
    (*db)->flush_pool = NULL;
    (*db)->compaction_pool = NULL;
    (*db)->total_memory = get_total_memory();
    (*db)->available_memory = get_available_memory();

    if ((*db)->total_memory > 0)
    {
        TDB_DEBUG_LOG("System memory: total=" TDB_SIZE_FMT " MB, available=" TDB_SIZE_FMT " MB",
                      TDB_SIZE_CAST((*db)->total_memory / (1024 * 1024)),
                      TDB_SIZE_CAST((*db)->available_memory / (1024 * 1024)));
    }
    else
    {
        TDB_DEBUG_LOG("Warning: Could not determine system memory, memory checks disabled");
        (*db)->total_memory = SIZE_MAX;
        (*db)->available_memory = SIZE_MAX;
    }

    if (pthread_rwlock_init(&(*db)->db_lock, NULL) != 0)
    {
        free(*db);
        return TDB_ERR_LOCK;
    }
    size_t cache_capacity = (*db)->config.max_open_file_handles > 0
                                ? (size_t)(*db)->config.max_open_file_handles
                                : TDB_DEFAULT_MAX_OPEN_FILE_HANDLES;

    (*db)->block_manager_cache = lru_cache_new(cache_capacity);
    if (!(*db)->block_manager_cache)
    {
        pthread_rwlock_destroy(&(*db)->db_lock);
        free(*db);
        return TDB_ERR_MEMORY;
    }
    TDB_DEBUG_LOG("Block manager cache initialized with capacity: %d", (int)cache_capacity);

    /* create thread pools */
    int num_flush_threads = (*db)->config.num_flush_threads > 0 ? (*db)->config.num_flush_threads
                                                                : TDB_DEFAULT_THREAD_POOL_SIZE;
    int num_compaction_threads = (*db)->config.num_compaction_threads > 0
                                     ? (*db)->config.num_compaction_threads
                                     : TDB_DEFAULT_THREAD_POOL_SIZE;

    (*db)->flush_pool = thread_pool_create(num_flush_threads);
    if (!(*db)->flush_pool)
    {
        lru_cache_free((*db)->block_manager_cache);
        pthread_rwlock_destroy(&(*db)->db_lock);
        free(*db);
        return TDB_ERR_THREAD;
    }
    TDB_DEBUG_LOG("Flush thread pool created with %d threads", num_flush_threads);

    (*db)->compaction_pool = thread_pool_create(num_compaction_threads);
    if (!(*db)->compaction_pool)
    {
        thread_pool_destroy((*db)->flush_pool);
        lru_cache_free((*db)->block_manager_cache);
        pthread_rwlock_destroy(&(*db)->db_lock);
        free(*db);
        return TDB_ERR_THREAD;
    }
    TDB_DEBUG_LOG("Compaction thread pool created with %d threads", num_compaction_threads);

    if (mkdir_p(config->db_path) == -1)
    {
        pthread_rwlock_destroy(&(*db)->db_lock);
        free(*db);
        return TDB_ERR_IO;
    }

    TDB_DEBUG_LOG("Database directory created/verified");

    /* clean up any temp files from incomplete operations */
    DIR *cleanup_dir = opendir(config->db_path);
    if (cleanup_dir)
    {
        struct dirent *entry;
        while ((entry = readdir(cleanup_dir)) != NULL)
        {
            if (strstr(entry->d_name, TDB_TEMP_EXT) != NULL)
            {
                char temp_file_path[TDB_MAX_PATH_LENGTH];
                (void)snprintf(temp_file_path, TDB_MAX_PATH_LENGTH, "%s" PATH_SEPARATOR "%s",
                               config->db_path, entry->d_name);
                TDB_DEBUG_LOG("Cleaning up incomplete temp file: %s", temp_file_path);
                unlink(temp_file_path);
            }
        }
        closedir(cleanup_dir);
    }

    DIR *dir = opendir(config->db_path);
    if (dir)
    {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL)
        {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
            {
                tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
                if (tidesdb_create_column_family(*db, entry->d_name, &cf_config) == -1)
                {
                    closedir(dir);
                    tidesdb_close(*db);
                    return -1;
                }
            }
        }
        closedir(dir);
    }

    return 0;
}

int tidesdb_close(tidesdb_t *db)
{
    if (!db) return TDB_ERR_INVALID_ARGS;

    /* shutdown thread pools -- threads should exit quickly since we signal shutdown */
    if (db->flush_pool)
    {
        thread_pool_destroy(db->flush_pool);
        db->flush_pool = NULL;
    }
    if (db->compaction_pool)
    {
        thread_pool_destroy(db->compaction_pool);
        db->compaction_pool = NULL;
    }

    pthread_rwlock_wrlock(&db->db_lock);

    for (int i = 0; i < db->num_cfs; i++)
    {
        tidesdb_column_family_t *cf = db->column_families[i];
        if (!cf) continue;

        /* clear immutable memtables queue without flushing
         * background flush threads have been stopped
         * need to release both queue reference AND creation reference */
        pthread_mutex_lock(&cf->flush_lock);
        tidesdb_memtable_t *mt;
        while ((mt = (tidesdb_memtable_t *)queue_dequeue(cf->immutable_memtables)) != NULL)
        {
            /* close WAL if still open */
            if (mt->wal)
            {
                block_manager_close(mt->wal);
                mt->wal = NULL;
            }
            /* release queue reference */
            int remaining_refs = tidesdb_memtable_release(mt);
            /* if memtable wasn't freed (ref_count > 0), release creation reference too
             * (normally done by flush task via tidesdb_memtable_free)
             * if ref_count reached 0, memtable was already freed by release */
            if (remaining_refs > 0)
            {
                tidesdb_memtable_free(mt);
            }
        }
        pthread_mutex_unlock(&cf->flush_lock);

        tidesdb_memtable_t *active_mt = atomic_load(&cf->active_memtable);
        if (active_mt)
        {
            if (active_mt->wal)
            {
                block_manager_close(active_mt->wal);
                active_mt->wal = NULL;
            }

            tidesdb_memtable_free(active_mt);
        }

        if (cf->immutable_memtables) queue_free(cf->immutable_memtables);

        int num_ssts = atomic_load(&cf->num_sstables);
        for (int j = 0; j < num_ssts; j++)
        {
            if (cf->sstables[j])
            {
                /* release the array's reference -- sstable will be freed when ref count reaches 0
                 */
                tidesdb_sstable_release(cf->sstables[j]);
            }
        }
        free(cf->sstables);

        (void)pthread_rwlock_destroy(&cf->cf_lock);
        (void)pthread_mutex_destroy(&cf->flush_lock);
        (void)pthread_mutex_destroy(&cf->compaction_lock);
        (void)pthread_mutex_destroy(&cf->memtable_write_lock);

        free(cf);
        db->column_families[i] = NULL;
    }

    free(db->column_families);

    /* close all cached block managers AFTER freeing sstables
     * sstable_free needs to access the cache to evict entries */
    if (db->block_manager_cache)
    {
        TDB_DEBUG_LOG("Freeing block manager cache");
        lru_cache_free(db->block_manager_cache);
    }

    pthread_rwlock_unlock(&db->db_lock);
    pthread_rwlock_destroy(&db->db_lock);
    free(db);

    return 0;
}

int tidesdb_create_column_family(tidesdb_t *db, const char *name,
                                 const tidesdb_column_family_config_t *config)
{
    if (!db || !name) return TDB_ERR_INVALID_ARGS;
    if (name[0] == '\0') return TDB_ERR_INVALID_NAME; /* empty name not allowed */
    if (strlen(name) >= TDB_MAX_CF_NAME_LENGTH) return TDB_ERR_INVALID_NAME;

    TDB_DEBUG_LOG("Creating column family: %s", name);

    pthread_rwlock_wrlock(&db->db_lock);

    for (int i = 0; i < db->num_cfs; i++)
    {
        if (strcmp(db->column_families[i]->name, name) == 0)
        {
            TDB_DEBUG_LOG("Column family %s already exists", name);
            pthread_rwlock_unlock(&db->db_lock);
            return 0;
        }
    }

    tidesdb_column_family_t *cf = malloc(sizeof(tidesdb_column_family_t));
    if (!cf)
    {
        pthread_rwlock_unlock(&db->db_lock);
        return TDB_ERR_MEMORY;
    }

    strncpy(cf->name, name, TDB_MAX_CF_NAME_LENGTH - 1);
    cf->name[TDB_MAX_CF_NAME_LENGTH - 1] = '\0';
    memset(cf->comparator_name, 0, TDB_MAX_COMPARATOR_NAME);
    cf->db = db;
    atomic_init(&cf->active_memtable, NULL);
    cf->immutable_memtables = NULL;
    cf->sstables = NULL;
    atomic_init(&cf->num_sstables, 0);
    cf->sstable_array_capacity = 0;
    atomic_init(&cf->next_sstable_id, 0);
    atomic_init(&cf->next_memtable_id, 0);
    atomic_init(&cf->is_dropping, 0);
    atomic_init(&cf->active_operations, 0);
    memset(&cf->cf_lock, 0, sizeof(pthread_rwlock_t));
    memset(&cf->flush_lock, 0, sizeof(pthread_mutex_t));
    memset(&cf->compaction_lock, 0, sizeof(pthread_mutex_t));

    if (config)
    {
        memcpy(&cf->config, config, sizeof(tidesdb_column_family_config_t));
    }
    else
    {
        cf->config = tidesdb_default_column_family_config();
    }

    /* validate config parameters */
    if (cf->config.memtable_flush_size == 0)
    {
        free(cf);
        pthread_rwlock_unlock(&db->db_lock);
        return TDB_ERR_INVALID_ARGS;
    }
    if (cf->config.max_sstables_before_compaction < 2)
    {
        free(cf);
        pthread_rwlock_unlock(&db->db_lock);
        return TDB_ERR_INVALID_ARGS;
    }
    if (cf->config.enable_bloom_filter &&
        (cf->config.bloom_filter_fp_rate <= 0.0 || cf->config.bloom_filter_fp_rate > 1.0))
    {
        free(cf);
        pthread_rwlock_unlock(&db->db_lock);
        return TDB_ERR_INVALID_ARGS;
    }

    /* lookup comparator by name */
    const char *cmp_name = cf->config.comparator_name[0] ? cf->config.comparator_name : "memcmp";
    skip_list_comparator_fn cmp_fn = tidesdb_get_comparator(cmp_name);

    if (!cmp_fn)
    {
        TDB_DEBUG_LOG("Comparator '%s' not found in registry", cmp_name);
        free(cf);
        pthread_rwlock_unlock(&db->db_lock);
        return TDB_ERR_COMPARATOR_NOT_FOUND;
    }

    /* save comparator name to cf */
    size_t cmp_len = strlen(cmp_name);
    if (cmp_len >= TDB_MAX_COMPARATOR_NAME) cmp_len = TDB_MAX_COMPARATOR_NAME - 1;
    memcpy(cf->comparator_name, cmp_name, cmp_len);
    cf->comparator_name[cmp_len] = '\0';

    /* if config had empty comparator_name, save the resolved default to config */
    if (cf->config.comparator_name[0] == '\0')
    {
        size_t cfg_cmp_len = strlen(cmp_name);
        if (cfg_cmp_len >= TDB_MAX_COMPARATOR_NAME) cfg_cmp_len = TDB_MAX_COMPARATOR_NAME - 1;
        memcpy(cf->config.comparator_name, cmp_name, cfg_cmp_len);
        cf->config.comparator_name[cfg_cmp_len] = '\0';
    }

    TDB_DEBUG_LOG("Column family '%s' using comparator '%s'", name, cf->comparator_name);

    if (pthread_rwlock_init(&cf->cf_lock, NULL) != 0)
    {
        free(cf);
        pthread_rwlock_unlock(&db->db_lock);
        return TDB_ERR_LOCK;
    }

    if (pthread_mutex_init(&cf->flush_lock, NULL) != 0)
    {
        pthread_rwlock_destroy(&cf->cf_lock);
        free(cf);
        pthread_rwlock_unlock(&db->db_lock);
        return TDB_ERR_LOCK;
    }

    if (pthread_mutex_init(&cf->compaction_lock, NULL) != 0)
    {
        pthread_rwlock_destroy(&cf->cf_lock);
        pthread_mutex_destroy(&cf->flush_lock);
        free(cf);
        pthread_rwlock_unlock(&db->db_lock);
        return TDB_ERR_LOCK;
    }

    if (pthread_mutex_init(&cf->memtable_write_lock, NULL) != 0)
    {
        pthread_mutex_destroy(&cf->compaction_lock);
        pthread_mutex_destroy(&cf->flush_lock);
        pthread_rwlock_destroy(&cf->cf_lock);
        free(cf);
        pthread_rwlock_unlock(&db->db_lock);
        return TDB_ERR_LOCK;
    }

    char cf_path[TDB_MAX_PATH_LENGTH];
    get_cf_path(db, name, cf_path);
    if (mkdir_p(cf_path) == -1)
    {
        pthread_rwlock_destroy(&cf->cf_lock);
        pthread_mutex_destroy(&cf->flush_lock);
        pthread_mutex_destroy(&cf->compaction_lock);
        pthread_mutex_destroy(&cf->memtable_write_lock);
        free(cf);
        pthread_rwlock_unlock(&db->db_lock);
        return TDB_ERR_IO;
    }

    /* try to load existing config from .cfc file (recovery scenario) */
    if (load_cf_config(cf) == 0)
    {
        TDB_DEBUG_LOG("Loaded existing config for column family: %s", name);
    }
    else
    {
        /* no existing config, save the provided/default config */
        if (save_cf_config(cf) != 0)
        {
            TDB_DEBUG_LOG("Warning: Failed to save initial config for column family: %s", name);
        }
        else
        {
            TDB_DEBUG_LOG("Saved initial config for column family: %s", name);
        }
    }

    /* initialize memtable IDs */
    atomic_store(&cf->next_memtable_id, 0);

    /* create queue for immutable memtables */
    cf->immutable_memtables = queue_new();
    if (!cf->immutable_memtables)
    {
        pthread_rwlock_destroy(&cf->cf_lock);
        pthread_mutex_destroy(&cf->flush_lock);
        pthread_mutex_destroy(&cf->compaction_lock);
        pthread_mutex_destroy(&cf->memtable_write_lock);
        free(cf);
        pthread_rwlock_unlock(&db->db_lock);
        return TDB_ERR_MEMORY;
    }

    /* create initial active memtable */
    tidesdb_memtable_t *initial_mt = tidesdb_memtable_new(cf);
    if (!initial_mt)
    {
        queue_free(cf->immutable_memtables);
        pthread_rwlock_destroy(&cf->cf_lock);
        pthread_mutex_destroy(&cf->flush_lock);
        pthread_mutex_destroy(&cf->compaction_lock);
        pthread_mutex_destroy(&cf->memtable_write_lock);
        free(cf);
        pthread_rwlock_unlock(&db->db_lock);
        return TDB_ERR_MEMORY;
    }
    atomic_store(&cf->active_memtable, initial_mt);

    /* init sstables array (grows dynamically) */
    cf->sstables = NULL;
    cf->sstable_array_capacity = 0;
    /* recover from WAL files if they exist */
    typedef struct
    {
        uint64_t id;
        char path[TDB_MAX_PATH_LENGTH];
    } wal_file_t;

    wal_file_t *wal_files = NULL;
    int num_wal_files = 0;
    int wal_capacity = 0;

    DIR *wal_dir = opendir(cf_path);
    if (wal_dir)
    {
        struct dirent *entry;
        while ((entry = readdir(wal_dir)) != NULL)
        {
            if (strstr(entry->d_name, TDB_WAL_PREFIX) && strstr(entry->d_name, TDB_WAL_EXT))
            {
                /* parse WAL ID */
                const char *id_start = entry->d_name + strlen(TDB_WAL_PREFIX);
                char *endptr;
                uint64_t wal_id = strtoul(id_start, &endptr, 10);
                if (endptr != id_start && strstr(endptr, TDB_WAL_EXT))
                {
                    /* grow array if needed */
                    if (num_wal_files >= wal_capacity)
                    {
                        int new_cap = wal_capacity == 0 ? 4 : wal_capacity * 2;
                        wal_file_t *new_wals =
                            realloc(wal_files, (size_t)new_cap * sizeof(wal_file_t));
                        if (new_wals)
                        {
                            wal_files = new_wals;
                            wal_capacity = new_cap;
                        }
                    }

                    if (num_wal_files < wal_capacity)
                    {
                        wal_files[num_wal_files].id = wal_id;
                        snprintf(wal_files[num_wal_files].path,
                                 sizeof(wal_files[num_wal_files].path), "%s" PATH_SEPARATOR "%s",
                                 cf_path, entry->d_name);
                        num_wal_files++;

                        /* update next_memtable_id */
                        if (wal_id >= atomic_load(&cf->next_memtable_id))
                        {
                            atomic_store(&cf->next_memtable_id, wal_id + 1);
                        }
                    }
                }
            }
        }
        closedir(wal_dir);
    }

    /* sort WAL files by ID (oldest first) */
    for (int i = 0; i < num_wal_files - 1; i++)
    {
        for (int j = i + 1; j < num_wal_files; j++)
        {
            if (wal_files[i].id > wal_files[j].id)
            {
                wal_file_t temp = wal_files[i];
                wal_files[i] = wal_files[j];
                wal_files[j] = temp;
            }
        }
    }

    /* recover WAL files in order */
    for (int i = 0; i < num_wal_files; i++)
    {
        tidesdb_memtable_t *recovered_mt = malloc(sizeof(tidesdb_memtable_t));
        if (!recovered_mt) continue;

        recovered_mt->id = wal_files[i].id;

        char mt_path[TDB_MAX_PATH_LENGTH];
        snprintf(mt_path, sizeof(mt_path), "%s" PATH_SEPARATOR "%s", cf_path, wal_files[i].path);

        recovered_mt->created_at = get_file_mod_time(mt_path);
        atomic_store(&recovered_mt->ref_count, 1); /* initial reference */
        if (pthread_mutex_init(&recovered_mt->ref_lock, NULL) != 0)
        {
            free(recovered_mt);
            continue;
        }

        skip_list_comparator_fn recovered_cmp_fn = tidesdb_get_comparator(cf->comparator_name);
        if (skip_list_new_with_comparator(&recovered_mt->memtable, cf->config.sl_max_level,
                                          cf->config.sl_probability, recovered_cmp_fn, NULL) == -1)
        {
            free(recovered_mt);
            continue;
        }

        /* open WAL file directly (not cached by engine) */
        if (block_manager_open_with_cache(&recovered_mt->wal, wal_files[i].path,
                                          convert_sync_mode((int)cf->config.sync_mode),
                                          cf->config.block_manager_cache_size) == -1)
        {
            skip_list_free(recovered_mt->memtable);
            free(recovered_mt);
            continue;
        }

        /* recover entries from WAL into memtable */
        int entries_recovered = 0;
        block_manager_cursor_t *cursor = NULL;
        if (block_manager_cursor_init(&cursor, recovered_mt->wal) == 0)
        {
            if (block_manager_cursor_goto_first(cursor) == 0)
            {
                do
                {
                    block_manager_block_t *block = block_manager_cursor_read(cursor);
                    if (block)
                    {
                        /* handle batched WAL entries -- multiple entries per block */
                        uint8_t *data_ptr = (uint8_t *)block->data;
                        size_t offset = 0;

                        while (offset + TDB_KV_HEADER_SIZE <= block->size)
                        {
                            uint8_t version, flags;
                            uint32_t key_size, value_size;
                            int64_t ttl;

                            deserialize_kv_header(data_ptr + offset, &version, &flags, &key_size,
                                                  &value_size, &ttl);
                            offset += TDB_KV_HEADER_SIZE;

                            /* validate we have enough data for key and value */
                            if (offset + key_size + value_size > block->size)
                            {
                                break; /* incomp entry, stop */
                            }

                            uint8_t *key = data_ptr + offset;
                            offset += key_size;
                            uint8_t *value = data_ptr + offset;
                            offset += value_size;

                            if (flags & TDB_KV_FLAG_TOMBSTONE)
                            {
                                /* tombstone */
                                uint8_t empty = 0;
                                skip_list_put(recovered_mt->memtable, key, key_size, &empty, 0, 0);
                                skip_list_delete(recovered_mt->memtable, key, key_size);
                            }
                            else
                            {
                                /* normal entry */
                                skip_list_put(recovered_mt->memtable, key, key_size, value,
                                              value_size, (time_t)ttl);
                            }
                            entries_recovered++;
                        }
                        block_manager_block_free(block);
                    }
                } while (block_manager_cursor_next(cursor) == 0);
            }
            block_manager_cursor_free(cursor);
        }

        TDB_DEBUG_LOG("WAL recovery for column family: %s (wal id: " TDB_U64_FMT ", entries: %d)",
                      cf->name, (unsigned long long)wal_files[i].id, entries_recovered);

        /* if this is the newest WAL, make it active; otherwise add to immutable queue */
        if (i == num_wal_files - 1)
        {
            /* newest, replace the empty active memtable */
            tidesdb_memtable_t *old_mt = atomic_load(&cf->active_memtable);
            tidesdb_memtable_free(old_mt);
            atomic_store(&cf->active_memtable, recovered_mt);
        }
        else
        {
            /* older, add to immutable queue for flushing */
            queue_enqueue(cf->immutable_memtables, recovered_mt);
        }
    }

    if (num_wal_files > 0)
    {
        TDB_DEBUG_LOG("WAL recovery completed for column family: %s (%d WAL files processed)",
                      cf->name, num_wal_files);
    }

    if (wal_files) free(wal_files);

    pthread_rwlock_unlock(&db->db_lock);

    /* load existing sstables */
    DIR *dir = opendir(cf_path);
    if (dir)
    {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL)
        {
            if (strstr(entry->d_name, TDB_SSTABLE_EXT))
            {
                const char *id_start = entry->d_name + strlen(TDB_SSTABLE_PREFIX);
                char *endptr;
                uint64_t sstable_id = strtoul(id_start, &endptr, 10);
                if (endptr != id_start && strstr(endptr, TDB_SSTABLE_EXT))
                {
                    tidesdb_sstable_t *sst = NULL;
                    if (tidesdb_load_sstable(cf, sstable_id, &sst) == 0)
                    {
                        /* grow array if needed */
                        if (cf->num_sstables >= cf->sstable_array_capacity)
                        {
                            int new_cap = cf->sstable_array_capacity == 0
                                              ? 8
                                              : cf->sstable_array_capacity * 2;
                            tidesdb_sstable_t **new_ssts = realloc(
                                cf->sstables, (size_t)new_cap * sizeof(tidesdb_sstable_t *));
                            if (new_ssts)
                            {
                                cf->sstables = new_ssts;
                                cf->sstable_array_capacity = new_cap;
                            }
                        }

                        if (cf->num_sstables < cf->sstable_array_capacity)
                        {
                            cf->sstables[cf->num_sstables] = sst;
                            atomic_fetch_add(&cf->num_sstables, 1);
                            if (sstable_id >= atomic_load(&cf->next_sstable_id))
                            {
                                atomic_store(&cf->next_sstable_id, sstable_id + 1);
                            }
                        }
                        else
                        {
                            /* failed to grow array, free the loaded sstable */
                            if (sst->index) succinct_trie_free(sst->index);
                            if (sst->bloom_filter) bloom_filter_free(sst->bloom_filter);
                            if (sst->min_key) free(sst->min_key);
                            if (sst->max_key) free(sst->max_key);
                            pthread_mutex_destroy(&sst->ref_lock);
                            free(sst);
                        }
                    }
                }
            }
        }
        closedir(dir);
    }

    /* sort sstables by ID (oldest to newest) for correct read semantics */
    if (atomic_load(&cf->num_sstables) > 1)
    {
        int num_ssts = atomic_load(&cf->num_sstables);

        for (int i = 0; i < num_ssts - 1; i++)
        {
            for (int j = 0; j < num_ssts - i - 1; j++)
            {
                if (cf->sstables[j]->id > cf->sstables[j + 1]->id)
                {
                    tidesdb_sstable_t *temp = cf->sstables[j];
                    cf->sstables[j] = cf->sstables[j + 1];
                    cf->sstables[j + 1] = temp;
                }
            }
        }
        TDB_DEBUG_LOG("Sorted %d SSTables by ID for column family: %s", num_ssts, cf->name);
    }

    TDB_DEBUG_LOG("SSTable recovery completed for column family: %s (%d sstables loaded)", cf->name,
                  atomic_load(&cf->num_sstables));

    /* submit any recovered memtables to flush pool and wait for completion */
    pthread_mutex_lock(&cf->flush_lock);
    int num_recovered_to_flush = (int)queue_size(cf->immutable_memtables);
    tidesdb_memtable_t *recovered_mt;
    while ((recovered_mt = (tidesdb_memtable_t *)queue_dequeue(cf->immutable_memtables)) != NULL)
    {
        pthread_mutex_unlock(&cf->flush_lock);
        thread_pool_submit(db->flush_pool, TASK_FLUSH, cf, recovered_mt);
        pthread_mutex_lock(&cf->flush_lock);
    }
    pthread_mutex_unlock(&cf->flush_lock);

    /* wait for all recovered memtable flushes to complete if configured
     * this ensures data is immediately queryable after tidesdb_open returns */
    if (num_recovered_to_flush > 0 && db->config.wait_for_wal_recovery)
    {
        TDB_DEBUG_LOG(
            "Waiting for %d recovered memtable flush(es) to complete for column family: %s",
            num_recovered_to_flush, cf->name);

        /* poll until all flushes complete (immutable queue becomes empty and stays empty)
         * we check twice with a small delay to ensure flushes have actually completed */
        int stable_count = 0;
        while (stable_count < 2)
        {
            usleep(db->config.wal_recovery_poll_interval_ms);
            pthread_mutex_lock(&cf->flush_lock);
            int current_size = (int)queue_size(cf->immutable_memtables);
            pthread_mutex_unlock(&cf->flush_lock);

            if (current_size == 0)
            {
                stable_count++;
            }
            else
            {
                stable_count = 0; /* reset if queue is not empty */
            }
        }

        TDB_DEBUG_LOG("All recovered memtable flushes completed for column family: %s", cf->name);
    }
    else if (num_recovered_to_flush > 0)
    {
        TDB_DEBUG_LOG(
            "Submitted %d recovered memtable(s) for background flush (wait_for_wal_recovery=false)",
            num_recovered_to_flush);
    }

    /* re-acquire db_lock to add CF to database */
    pthread_rwlock_wrlock(&db->db_lock);

    /* add to database */
    if (db->num_cfs >= db->cf_capacity)
    {
        int new_cap = db->cf_capacity == 0 ? 8 : db->cf_capacity * 2;
        tidesdb_column_family_t **new_cfs =
            realloc(db->column_families, (size_t)new_cap * sizeof(tidesdb_column_family_t *));
        if (!new_cfs)
        {
            /* cleanup on failure */
            tidesdb_memtable_t *active_mt = atomic_load(&cf->active_memtable);
            if (active_mt) tidesdb_memtable_free(active_mt);
            if (cf->immutable_memtables) queue_free(cf->immutable_memtables);

            /* free any loaded sstables */
            for (int i = 0; i < atomic_load(&cf->num_sstables); i++)
            {
                if (cf->sstables[i])
                {
                    tidesdb_sstable_t *sst = cf->sstables[i];
                    if (sst->index) succinct_trie_free(sst->index);
                    if (sst->bloom_filter) bloom_filter_free(sst->bloom_filter);
                    if (sst->min_key) free(sst->min_key);
                    if (sst->max_key) free(sst->max_key);
                    pthread_mutex_destroy(&sst->ref_lock);
                    free(sst);
                }
            }
            free(cf->sstables);

            pthread_rwlock_destroy(&cf->cf_lock);
            pthread_mutex_destroy(&cf->flush_lock);
            pthread_mutex_destroy(&cf->compaction_lock);
            free(cf);

            return TDB_ERR_MEMORY;
        }
        db->column_families = new_cfs;
        db->cf_capacity = new_cap;
    }

    db->column_families[db->num_cfs++] = cf;

    pthread_rwlock_unlock(&db->db_lock);
    return 0;
}

int tidesdb_drop_column_family(tidesdb_t *db, const char *name)
{
    if (!db || !name) return TDB_ERR_INVALID_ARGS;

    pthread_rwlock_wrlock(&db->db_lock);

    int found = -1;
    for (int i = 0; i < db->num_cfs; i++)
    {
        if (strcmp(db->column_families[i]->name, name) == 0)
        {
            found = i;
            break;
        }
    }

    if (found == -1)
    {
        pthread_rwlock_unlock(&db->db_lock);
        return TDB_ERR_NOT_FOUND;
    }

    tidesdb_column_family_t *cf = db->column_families[found];
    int cleanup_error = 0; /* track errors but continue cleanup */

    /* set dropping flag to stop new background operations */
    atomic_store(&cf->is_dropping, 1);

    /* wait for all active background operations to complete
     * operations check is_dropping and will decrement counter before exiting */
    while (atomic_load(&cf->active_operations) > 0)
    {
        /* spin-wait -- operations should complete quickly once they see is_dropping */
        sched_yield(); /* yield CPU to let other threads run */
    }

    /* clear immutable memtables queue without flushing
     * WAL will handle recovery on next open if needed */
    pthread_mutex_lock(&cf->flush_lock);
    tidesdb_memtable_t *mt;
    while ((mt = (tidesdb_memtable_t *)queue_dequeue(cf->immutable_memtables)) != NULL)
    {
        /* close WAL and free memtable without flushing */
        if (mt->wal)
        {
            block_manager_close(mt->wal);
            mt->wal = NULL;
        }
        /* tidesdb_memtable_free calls tidesdb_memtable_release internally */
        tidesdb_memtable_free(mt);
    }
    pthread_mutex_unlock(&cf->flush_lock);

    tidesdb_memtable_t *active_mt = atomic_load(&cf->active_memtable);
    if (active_mt)
    {
        if (active_mt->wal)
        {
            block_manager_close(active_mt->wal);
            active_mt->wal = NULL;
        }
    }

    if (cf->immutable_memtables)
    {
        pthread_mutex_lock(&cf->flush_lock);
        size_t queue_len = queue_size(cf->immutable_memtables);
        for (size_t i = 0; i < queue_len; i++)
        {
            tidesdb_memtable_t *peek_mt =
                (tidesdb_memtable_t *)queue_peek_at(cf->immutable_memtables, i);
            if (peek_mt && peek_mt->wal)
            {
                block_manager_close(peek_mt->wal);
                peek_mt->wal = NULL;
            }
        }
        pthread_mutex_unlock(&cf->flush_lock);
    }

    pthread_mutex_destroy(&cf->compaction_lock);
    pthread_mutex_destroy(&cf->memtable_write_lock);

    if (active_mt)
    {
        /* release the active memtable reference properly */
        tidesdb_memtable_release(active_mt);
    }

    if (cf->immutable_memtables)
    {
        tidesdb_memtable_t *cleanup_mt;
        while ((cleanup_mt = (tidesdb_memtable_t *)queue_dequeue(cf->immutable_memtables)) != NULL)
        {
            /* release queue reference properly */
            tidesdb_memtable_release(cleanup_mt);
        }
        queue_free(cf->immutable_memtables);
    }

    int num_ssts = atomic_load(&cf->num_sstables);
    for (int i = 0; i < num_ssts; i++)
    {
        if (cf->sstables[i])
        {
            /* release the array's reference -- SSTable will be freed when ref count reaches 0 */
            tidesdb_sstable_release(cf->sstables[i]);
        }
    }
    free(cf->sstables);

    /* now scan directory and delete ALL files and subdirectories (handles are closed) */
    char cf_path[TDB_MAX_PATH_LENGTH];
    get_cf_path(db, cf->name, cf_path);
    DIR *cleanup_dir = opendir(cf_path);
    if (cleanup_dir)
    {
        struct dirent *entry;
        while ((entry = readdir(cleanup_dir)) != NULL)
        {
            /* skip . and .. */
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            {
                continue;
            }

            char file_path[TDB_MAX_PATH_LENGTH];
            snprintf(file_path, sizeof(file_path), "%s" PATH_SEPARATOR "%s", cf_path,
                     entry->d_name);

            /* check if it's a directory or file */
            struct stat st;
            if (stat(file_path, &st) == 0)
            {
                if (S_ISDIR(st.st_mode))
                {
                    /* recursively delete subdirectory (shouldn't normally exist) */
                    rmdir(file_path); /* try to remove if empty */
                }
                else
                {
                    /* delete file (wal, sst, config, temp, etc.) */
                    if (unlink(file_path) == -1 && errno != ENOENT)
                    {
                        cleanup_error = TDB_ERR_IO;
                    }
                }
            }
        }
        closedir(cleanup_dir);
    }

    /* delete directory (should now be empty) */
    if (rmdir(cf_path) == -1 && errno != ENOENT)
    {
        cleanup_error = TDB_ERR_IO;
    }

    pthread_rwlock_destroy(&cf->cf_lock);
    pthread_mutex_destroy(&cf->flush_lock);
    pthread_mutex_destroy(&cf->compaction_lock);
    pthread_mutex_destroy(&cf->memtable_write_lock);
    free(cf);

    /* remove from array */
    for (int i = found; i < db->num_cfs - 1; i++)
    {
        db->column_families[i] = db->column_families[i + 1];
    }
    db->num_cfs--;

    pthread_rwlock_unlock(&db->db_lock);

    (void)cleanup_error;
    return 0;
}

tidesdb_column_family_t *tidesdb_get_column_family(tidesdb_t *db, const char *name)
{
    if (!db || !name) return NULL;

    pthread_rwlock_rdlock(&db->db_lock);

    for (int i = 0; i < db->num_cfs; i++)
    {
        if (strcmp(db->column_families[i]->name, name) == 0)
        {
            tidesdb_column_family_t *cf = db->column_families[i];
            pthread_rwlock_unlock(&db->db_lock);
            return cf;
        }
    }

    pthread_rwlock_unlock(&db->db_lock);
    return NULL;
}

int tidesdb_list_column_families(tidesdb_t *db, char ***names, int *count)
{
    if (!db || !names || !count) return TDB_ERR_INVALID_ARGS;

    pthread_rwlock_rdlock(&db->db_lock);

    *count = db->num_cfs;

    if (*count == 0)
    {
        *names = NULL;
        pthread_rwlock_unlock(&db->db_lock);
        return 0;
    }

    /* alloc array of string pointers */
    *names = malloc(sizeof(char *) * (size_t)(*count));
    if (!*names)
    {
        pthread_rwlock_unlock(&db->db_lock);
        return TDB_ERR_MEMORY;
    }

    /* copy each column family name */
    for (int i = 0; i < *count; i++)
    {
        (*names)[i] = malloc(TDB_MAX_CF_NAME_LENGTH);
        if (!(*names)[i])
        {
            /* free previously allocated names */
            for (int j = 0; j < i; j++)
            {
                free((*names)[j]);
            }
            free(*names);
            pthread_rwlock_unlock(&db->db_lock);
            return TDB_ERR_MEMORY;
        }
        size_t name_len = strlen(db->column_families[i]->name);
        if (name_len >= TDB_MAX_CF_NAME_LENGTH) name_len = TDB_MAX_CF_NAME_LENGTH - 1;
        memcpy((*names)[i], db->column_families[i]->name, name_len);
        (*names)[i][name_len] = '\0';
    }

    pthread_rwlock_unlock(&db->db_lock);
    return 0;
}

int tidesdb_get_column_family_stats(tidesdb_t *db, const char *name,
                                    tidesdb_column_family_stat_t **stats)
{
    if (!db || !name || !stats) return TDB_ERR_INVALID_ARGS;

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, name);
    if (!cf) return TDB_ERR_NOT_FOUND;

    *stats = malloc(sizeof(tidesdb_column_family_stat_t));
    if (!*stats) return TDB_ERR_MEMORY;

    pthread_rwlock_rdlock(&cf->cf_lock);

    /* copy basic info */
    size_t stats_name_len = strlen(cf->name);
    if (stats_name_len >= TDB_MAX_CF_NAME_LENGTH) stats_name_len = TDB_MAX_CF_NAME_LENGTH - 1;
    memcpy((*stats)->name, cf->name, stats_name_len);
    (*stats)->name[stats_name_len] = '\0';

    size_t stats_cmp_len = strlen(cf->comparator_name);
    if (stats_cmp_len >= TDB_MAX_COMPARATOR_NAME) stats_cmp_len = TDB_MAX_COMPARATOR_NAME - 1;
    memcpy((*stats)->comparator_name, cf->comparator_name, stats_cmp_len);
    (*stats)->comparator_name[stats_cmp_len] = '\0';
    (*stats)->num_sstables = atomic_load(&cf->num_sstables);

    /* calc total ssts size */
    (*stats)->total_sstable_size = 0;
    for (int i = 0; i < (*stats)->num_sstables; i++)
    {
        if (cf->sstables[i] && cf->sstables[i]->block_manager)
        {
            tidesdb_sstable_acquire(cf->sstables[i]);
            uint64_t size = 0;
            if (block_manager_get_size(cf->sstables[i]->block_manager, &size) == 0)
            {
                (*stats)->total_sstable_size += size;
            }
            tidesdb_sstable_release(cf->sstables[i]);
        }
    }

    /* memtable stats */
    tidesdb_memtable_t *active_mt = atomic_load(&cf->active_memtable);
    if (active_mt && active_mt->memtable)
    {
        tidesdb_memtable_acquire(active_mt);
        (*stats)->memtable_size = (size_t)skip_list_get_size(active_mt->memtable);
        (*stats)->memtable_entries = skip_list_count_entries(active_mt->memtable);
        tidesdb_memtable_release(active_mt);
    }
    else
    {
        (*stats)->memtable_size = 0;
        (*stats)->memtable_entries = 0;
    }

    /* copy config */
    memcpy(&(*stats)->config, &cf->config, sizeof(tidesdb_column_family_config_t));

    pthread_rwlock_unlock(&cf->cf_lock);
    return 0;
}

/*
 * tidesdb_memtable_new
 * creates a new memtable
 * @param cf column family
 * @return new memtable on success, NULL on failure
 */
static tidesdb_memtable_t *tidesdb_memtable_new(tidesdb_column_family_t *cf)
{
    if (!cf) return NULL;

    tidesdb_memtable_t *mt = malloc(sizeof(tidesdb_memtable_t));
    if (!mt) return NULL;

    mt->id = atomic_fetch_add(&cf->next_memtable_id, 1);
    /* check for overflow. safe because WALs are deleted after flush; old ids are expired */
    if (mt->id == UINT64_MAX)
    {
        TDB_DEBUG_LOG("Memtable ID overflow for CF '%s', resetting to 0", cf->name);
        atomic_store(&cf->next_memtable_id, 0);
        mt->id = 0;
    }

    mt->created_at = time(NULL);
    atomic_store(&mt->ref_count, 1); /* initial reference for active memtable */

    if (pthread_mutex_init(&mt->ref_lock, NULL) != 0)
    {
        free(mt);
        return NULL;
    }

    skip_list_comparator_fn cmp_fn = tidesdb_get_comparator(cf->comparator_name);
    if (skip_list_new_with_comparator(&mt->memtable, cf->config.sl_max_level,
                                      cf->config.sl_probability, cmp_fn, NULL) == -1)
    {
        pthread_mutex_destroy(&mt->ref_lock);
        free(mt);
        return NULL;
    }

    char wal_path[TDB_MAX_PATH_LENGTH];
    snprintf(wal_path, sizeof(wal_path),
             "%s" PATH_SEPARATOR "%s" PATH_SEPARATOR TDB_WAL_PREFIX "%" PRIu64 TDB_WAL_EXT,
             cf->db->config.db_path, cf->name, mt->id);

    if (block_manager_open_with_cache(&mt->wal, wal_path,
                                      convert_sync_mode((int)cf->config.sync_mode),
                                      cf->config.block_manager_cache_size) == -1)
    {
        skip_list_free(mt->memtable);
        pthread_mutex_destroy(&mt->ref_lock);
        free(mt);
        return NULL;
    }

    return mt;
}

/*
 * tidesdb_memtable_free
 * frees a memtable
 * @param mt memtable to free
 */
static void tidesdb_memtable_free(tidesdb_memtable_t *mt)
{
    if (!mt) return;

    /* decrement reference count
     * tidesdb_memtable_release will automatically free the memtable if ref_count reaches 0 */
    (void)tidesdb_memtable_release(mt);
}

/*
 * tidesdb_rotate_memtable
 * rotates the active memtable to a new one
 * @param cf column family
 * @return 0 on success, -1 on failure
 */
static int tidesdb_rotate_memtable(tidesdb_column_family_t *cf)
{
    if (!cf) return -1;

    TDB_DEBUG_LOG("Rotating memtable for column family: %s", cf->name);

    /* allocate new memtable BEFORE acquiring lock to reduce lock hold time */
    tidesdb_memtable_t *new_memtable = tidesdb_memtable_new(cf);
    if (!new_memtable) return -1;

    pthread_mutex_lock(&cf->flush_lock);

    /* atomic_exchange is already atomic, no lock needed for swap */
    tidesdb_memtable_t *old_memtable = atomic_exchange(&cf->active_memtable, new_memtable);

    if (old_memtable)
    {
        tidesdb_memtable_acquire(old_memtable);

        if (queue_enqueue(cf->immutable_memtables, old_memtable) != 0)
        {
            atomic_store(&cf->active_memtable, old_memtable);
            tidesdb_memtable_release(old_memtable);
            tidesdb_memtable_free(new_memtable);
            pthread_mutex_unlock(&cf->flush_lock);
            return -1;
        }

        size_t immutable_count = queue_size(cf->immutable_memtables);
        TDB_DEBUG_LOG("Memtable rotated for column family: %s (old id: " TDB_U64_FMT
                      ", new id: " TDB_U64_FMT ", immutable queue size: %zu)",
                      cf->name, (unsigned long long)old_memtable->id,
                      (unsigned long long)new_memtable->id, immutable_count);

        TDB_DEBUG_LOG("Submitting flush task for column family: %s (memtable id: " TDB_U64_FMT ")",
                      cf->name, (unsigned long long)old_memtable->id);

        int submit_result = thread_pool_submit(cf->db->flush_pool, TASK_FLUSH, cf, old_memtable);

        if (submit_result != 0)
        {
            tidesdb_memtable_t *removed =
                (tidesdb_memtable_t *)queue_dequeue(cf->immutable_memtables);
            if (removed == old_memtable)
            {
                atomic_store(&cf->active_memtable, old_memtable);
                tidesdb_memtable_release(old_memtable);
                tidesdb_memtable_free(new_memtable);
            }
            else
            {
                if (removed)
                {
                    queue_enqueue(cf->immutable_memtables, removed);
                }
            }
            pthread_mutex_unlock(&cf->flush_lock);
            return -1;
        }

        pthread_mutex_unlock(&cf->flush_lock);
        return 0;
    }

    pthread_mutex_unlock(&cf->flush_lock);
    return 0;
}

/*
 * tidesdb_flush_memtable_to_sstable
 * flushes a memtable to an sstable
 * @param cf column family
 * @param mt memtable to flush
 * @return 0 on success, -1 on failure
 */
static int tidesdb_flush_memtable_to_sstable(tidesdb_column_family_t *cf, tidesdb_memtable_t *mt)
{
    if (!cf || !mt) return -1;

    TDB_DEBUG_LOG("Flushing memtable %" PRIu64 " for column family: %s", mt->id, cf->name);

    int entry_count = skip_list_count_entries(mt->memtable);
    TDB_DEBUG_LOG("Memtable has %d entries", entry_count);

    if (entry_count == 0)
    {
        TDB_DEBUG_LOG("Memtable is empty, skipping flush");
        return 0;
    }

    uint64_t sstable_id = atomic_fetch_add(&cf->next_sstable_id, 1);
    char sstable_path[TDB_MAX_PATH_LENGTH];
    get_sstable_path(cf, sstable_id, sstable_path);

    tidesdb_sstable_t *sst = malloc(sizeof(tidesdb_sstable_t));
    if (!sst)
    {
        return -1;
    }

    sst->id = sstable_id;
    sst->cf = cf;
    sst->min_key = NULL;
    sst->max_key = NULL;
    sst->num_entries = 0;
    sst->bloom_filter = NULL;
    sst->index = NULL;
    atomic_store(&sst->ref_count, 1);
    pthread_mutex_init(&sst->ref_lock, NULL);

    sst->block_manager = get_cached_block_manager(cf->db, sstable_path, cf->config.sync_mode,
                                                  cf->config.block_manager_cache_size);
    if (!sst->block_manager)
    {
        pthread_mutex_destroy(&sst->ref_lock);
        free(sst);
        return -1;
    }

    int num_entries = skip_list_count_entries(mt->memtable);

    /* create bloom filter only if enabled */
    if (cf->config.enable_bloom_filter)
    {
        TDB_DEBUG_LOG("Creating bloom filter (entries: %d, fp_rate: %f)", num_entries,
                      cf->config.bloom_filter_fp_rate);
        bloom_filter_new(&sst->bloom_filter, cf->config.bloom_filter_fp_rate, num_entries);
        if (!sst->bloom_filter)
        {
            TDB_DEBUG_LOG("Failed to create bloom filter");
            if (cf->db->block_manager_cache)
            {
                lru_cache_remove(cf->db->block_manager_cache, sstable_path);
            }
            pthread_mutex_destroy(&sst->ref_lock);
            free(sst);
            return -1;
        }
        TDB_DEBUG_LOG("Bloom filter created successfully");
    }

    /* create index builder only if block indexes are enabled */
    succinct_trie_builder_t *index_builder = NULL;
    if (cf->config.enable_block_indexes)
    {
        TDB_DEBUG_LOG("Creating succinct trie builder for index");
        skip_list_comparator_fn cmp_fn = tidesdb_get_comparator(cf->comparator_name);
        char cf_path[TDB_MAX_PATH_LENGTH];
        get_cf_path(cf->db, cf->name, cf_path);
        index_builder =
            succinct_trie_builder_new(cf_path, (succinct_trie_comparator_fn)cmp_fn, NULL);
        if (!index_builder)
        {
            TDB_DEBUG_LOG("Failed to create succinct trie builder");
            if (cf->db->block_manager_cache)
            {
                lru_cache_remove(cf->db->block_manager_cache, sstable_path);
            }
            if (sst->bloom_filter) bloom_filter_free(sst->bloom_filter);
            pthread_mutex_destroy(&sst->ref_lock);
            free(sst);
            return -1;
        }
        TDB_DEBUG_LOG("Succinct trie builder created successfully");
    }
    sst->index = NULL; /* will be built after adding all entries */

    TDB_DEBUG_LOG("Creating skip list cursor for flush");
    skip_list_cursor_t *cursor = skip_list_cursor_init(mt->memtable);
    if (!cursor)
    {
        TDB_DEBUG_LOG("Failed to create skip list cursor");
        if (cf->db->block_manager_cache)
        {
            lru_cache_remove(cf->db->block_manager_cache, sstable_path);
        }

        if (sst->bloom_filter) bloom_filter_free(sst->bloom_filter);
        if (index_builder) succinct_trie_builder_free(index_builder);
        pthread_mutex_destroy(&sst->ref_lock);
        free(sst);
        return -1;
    }
    TDB_DEBUG_LOG("Skip list cursor created successfully");

    skip_list_node_t *header = atomic_load_explicit(&mt->memtable->header, memory_order_acquire);
    skip_list_retain_node(header);
    if (cursor->current) skip_list_release_node(cursor->current);
    cursor->current = header;

    int write_successful = 1;
    int entries_written = 0;

    TDB_DEBUG_LOG("Starting to write entries from memtable to SSTable");

    while (skip_list_cursor_has_next(cursor))
    {
        /* check if database is shutting down -- abort flush early */
        if (cf->db->flush_pool && atomic_load(&cf->db->flush_pool->shutdown))
        {
            TDB_DEBUG_LOG("Shutdown detected, aborting flush");
            write_successful = 0;
            break;
        }

        if (skip_list_cursor_next(cursor) != 0) break;

        uint8_t *k = NULL, *v = NULL;
        size_t k_size = 0, v_size = 0;
        time_t ttl = 0;
        uint8_t deleted = 0;

        if (skip_list_cursor_get(cursor, &k, &k_size, &v, &v_size, &ttl, &deleted) == 0)
        {
            if (!sst->min_key)
            {
                sst->min_key = malloc(k_size);
                if (!sst->min_key)
                {
                    write_successful = 0;
                    break;
                }
                memcpy(sst->min_key, k, k_size);
                sst->min_key_size = k_size;
            }

            uint8_t *new_max_key = malloc(k_size);
            if (!new_max_key)
            {
                write_successful = 0;
                break;
            }

            if (sst->max_key) free(sst->max_key);
            sst->max_key = new_max_key;
            memcpy(sst->max_key, k, k_size);
            sst->max_key_size = k_size;

            uint8_t version = TDB_KV_FORMAT_VERSION;
            uint8_t flags = deleted ? TDB_KV_FLAG_TOMBSTONE : 0;
            uint32_t key_size = (uint32_t)k_size;
            uint32_t value_size = (uint32_t)v_size;
            int64_t ttl_val = (int64_t)ttl;

            size_t block_size = TDB_KV_HEADER_SIZE + k_size + v_size;
            uint8_t *block_data = malloc(block_size);
            if (!block_data)
            {
                write_successful = 0;
                break;
            }

            uint8_t *ptr = block_data;
            serialize_kv_header(ptr, version, flags, key_size, value_size, ttl_val);
            ptr += TDB_KV_HEADER_SIZE;
            memcpy(ptr, k, k_size);
            ptr += k_size;
            memcpy(ptr, v, v_size);

            uint8_t *final_data = block_data;
            size_t final_size = block_size;

            if (cf->config.enable_compression)
            {
                size_t compressed_size = 0;
                uint8_t *compressed = compress_data(block_data, block_size, &compressed_size,
                                                    cf->config.compression_algorithm);
                if (compressed)
                {
                    free(block_data);
                    final_data = compressed;
                    final_size = compressed_size;
                }
            }

            block_manager_block_t *block = block_manager_block_create(final_size, final_data);
            if (block)
            {
                long offset = block_manager_block_write(sst->block_manager, block);
                if (offset >= 0)
                {
                    if (sst->bloom_filter)
                    {
                        bloom_filter_add(sst->bloom_filter, k, k_size);
                    }
                    if (index_builder)
                    {
                        /* store byte offset for O(1) direct positioning */
                        succinct_trie_builder_add(index_builder, k, k_size, (int64_t)offset);
                    }
                    /* don't increment num_entries yet -- use local counter */
                    entries_written++;
                }
                else
                {
                    write_successful = 0;
                }
                block_manager_block_free(block);
            }
            else
            {
                write_successful = 0;
            }
            free(final_data);

            if (!write_successful) break;
        }
    }
    skip_list_cursor_free(cursor);

    TDB_DEBUG_LOG("Wrote %d entries to SSTable (write_successful=%d)", entries_written,
                  write_successful);

    if (!write_successful)
    {
        if (cf->db->block_manager_cache)
        {
            lru_cache_remove(cf->db->block_manager_cache, sstable_path);
        }

        if (sst->bloom_filter) bloom_filter_free(sst->bloom_filter);
        if (index_builder) succinct_trie_builder_free(index_builder);
        if (sst->min_key) free(sst->min_key);
        if (sst->max_key) free(sst->max_key);
        pthread_mutex_destroy(&sst->ref_lock);
        free(sst);

        remove(sstable_path);
        return -1;
    }

    /* build the succinct trie from the builder */
    if (index_builder)
    {
        TDB_DEBUG_LOG("Building succinct trie index for SSTable (entries: %d)", entries_written);
        sst->index = succinct_trie_builder_build(index_builder);
        /* builder is freed by build function */
        index_builder = NULL;

        if (!sst->index)
        {
            TDB_DEBUG_LOG("Failed to build succinct trie index for SSTable");
            if (cf->db->block_manager_cache)
            {
                lru_cache_remove(cf->db->block_manager_cache, sstable_path);
            }
            if (sst->bloom_filter) bloom_filter_free(sst->bloom_filter);
            if (sst->min_key) free(sst->min_key);
            if (sst->max_key) free(sst->max_key);
            pthread_mutex_destroy(&sst->ref_lock);
            free(sst);
            remove(sstable_path);
            return -1;
        }
        TDB_DEBUG_LOG("Successfully built succinct trie index for SSTable");
    }

    /* serialize bloom filter only if it exists */
    if (sst->bloom_filter)
    {
        size_t bloom_size = 0;
        uint8_t *bloom_data = bloom_filter_serialize(sst->bloom_filter, &bloom_size);
        if (bloom_data)
        {
            block_manager_block_t *bloom_block = block_manager_block_create(bloom_size, bloom_data);
            if (bloom_block)
            {
                block_manager_block_write(sst->block_manager, bloom_block);
                block_manager_block_free(bloom_block);
            }
            free(bloom_data);
        }
    }

    /* serialize index only if it exists */
    if (sst->index)
    {
        size_t index_size = 0;
        uint8_t *index_data = succinct_trie_serialize(sst->index, &index_size);
        if (index_data)
        {
            block_manager_block_t *index_block = block_manager_block_create(index_size, index_data);
            if (index_block)
            {
                block_manager_block_write(sst->block_manager, index_block);
                block_manager_block_free(index_block);
            }
            free(index_data);
        }
    }

    if (sst->min_key && sst->max_key)
    {
        uint32_t magic = TDB_SST_META_MAGIC;
        size_t metadata_size = sizeof(uint32_t) + sizeof(uint64_t) + sizeof(uint32_t) +
                               sst->min_key_size + sizeof(uint32_t) + sst->max_key_size;
        uint8_t *metadata = malloc(metadata_size);
        if (metadata)
        {
            uint8_t *ptr = metadata;
            encode_uint32_le(ptr, magic);
            ptr += sizeof(uint32_t);
            uint64_t num_entries_u64 = (uint64_t)sst->num_entries;
            encode_uint64_le(ptr, num_entries_u64);
            ptr += sizeof(uint64_t);
            uint32_t min_size = (uint32_t)sst->min_key_size;
            encode_uint32_le(ptr, min_size);
            ptr += sizeof(uint32_t);
            memcpy(ptr, sst->min_key, sst->min_key_size);
            ptr += sst->min_key_size;
            uint32_t max_size = (uint32_t)sst->max_key_size;
            encode_uint32_le(ptr, max_size);
            ptr += sizeof(uint32_t);
            memcpy(ptr, sst->max_key, sst->max_key_size);

            block_manager_block_t *metadata_block =
                block_manager_block_create(metadata_size, metadata);
            if (metadata_block)
            {
                block_manager_block_write(sst->block_manager, metadata_block);
                block_manager_block_free(metadata_block);
            }
            free(metadata);
        }
    }

    /* atomically store final num_entries now that all blocks and metadata are written */
    atomic_store(&sst->num_entries, entries_written);

    /* use flush_lock instead of cf_lock write lock to avoid blocking readers
     * flush_lock serializes flushes but doesn't block reads */
    pthread_mutex_lock(&cf->flush_lock);

    if (cf->num_sstables >= cf->sstable_array_capacity)
    {
        int new_cap = cf->sstable_array_capacity == 0 ? 8 : cf->sstable_array_capacity * 2;
        tidesdb_sstable_t **new_ssts =
            realloc(cf->sstables, (size_t)new_cap * sizeof(tidesdb_sstable_t *));
        if (!new_ssts)
        {
            pthread_mutex_unlock(&cf->flush_lock);

            if (cf->db->block_manager_cache)
            {
                lru_cache_remove(cf->db->block_manager_cache, sstable_path);
            }

            if (sst->bloom_filter) bloom_filter_free(sst->bloom_filter);
            if (sst->index) succinct_trie_free(sst->index);
            if (sst->min_key) free(sst->min_key);
            if (sst->max_key) free(sst->max_key);
            pthread_mutex_destroy(&sst->ref_lock);
            free(sst);

            remove(sstable_path);
            return -1;
        }

        /* initialize new slots to NULL */
        for (int i = cf->sstable_array_capacity; i < new_cap; i++)
        {
            new_ssts[i] = NULL;
        }

        cf->sstables = new_ssts;
        cf->sstable_array_capacity = new_cap;
    }

    int current_count = atomic_load(&cf->num_sstables);
    cf->sstables[current_count] = sst;
    /* ensure pointer write is visible before incrementing count */
    atomic_thread_fence(memory_order_release);
    atomic_fetch_add(&cf->num_sstables, 1);

    pthread_mutex_unlock(&cf->flush_lock);

    TDB_DEBUG_LOG("Successfully added SSTable to column family: %s (new count: %d)", cf->name,
                  atomic_load(&cf->num_sstables));

    if (mt->wal)
    {
        block_manager_close(mt->wal);
        mt->wal = NULL;

        char wal_path[TDB_MAX_PATH_LENGTH];
        snprintf(wal_path, sizeof(wal_path),
                 "%s" PATH_SEPARATOR "%s" PATH_SEPARATOR TDB_WAL_PREFIX "%" PRIu64 TDB_WAL_EXT,
                 cf->db->config.db_path, cf->name, mt->id);
        remove(wal_path);
    }

    return 0;
}

int tidesdb_update_column_family_config(tidesdb_t *db, const char *name,
                                        const tidesdb_column_family_update_config_t *update_config)
{
    if (!db || !name || !update_config) return TDB_ERR_INVALID_ARGS;

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, name);
    if (!cf) return TDB_ERR_NOT_FOUND;

    /* validate configuration values */
    if (update_config->memtable_flush_size == 0)
    {
        return TDB_ERR_INVALID_ARGS;
    }

    if (update_config->max_sstables_before_compaction < 2)
    {
        return TDB_ERR_INVALID_ARGS;
    }

    if (update_config->compaction_threads < 0)
    {
        return TDB_ERR_INVALID_ARGS;
    }

    if (update_config->sl_max_level < 1)
    {
        return TDB_ERR_INVALID_ARGS;
    }

    if (update_config->sl_probability <= 0.0f || update_config->sl_probability >= 1.0f)
    {
        return TDB_ERR_INVALID_ARGS;
    }

    if (update_config->enable_bloom_filter &&
        (update_config->bloom_filter_fp_rate <= 0.0 || update_config->bloom_filter_fp_rate >= 1.0))
    {
        return TDB_ERR_INVALID_ARGS;
    }

    if (update_config->background_compaction_interval < 0)
    {
        return TDB_ERR_INVALID_ARGS;
    }

    pthread_rwlock_wrlock(&cf->cf_lock);

    cf->config.memtable_flush_size = update_config->memtable_flush_size;
    cf->config.max_sstables_before_compaction = update_config->max_sstables_before_compaction;
    cf->config.compaction_threads = update_config->compaction_threads;
    cf->config.sl_max_level = update_config->sl_max_level;
    cf->config.sl_probability = update_config->sl_probability;
    cf->config.enable_bloom_filter = update_config->enable_bloom_filter;
    cf->config.bloom_filter_fp_rate = update_config->bloom_filter_fp_rate;
    cf->config.enable_background_compaction = update_config->enable_background_compaction;
    cf->config.background_compaction_interval = update_config->background_compaction_interval;
    cf->config.block_manager_cache_size = update_config->block_manager_cache_size;
    cf->config.sync_mode = update_config->sync_mode;

    int save_result = save_cf_config(cf);

    pthread_rwlock_unlock(&cf->cf_lock);

    if (save_result != 0)
    {
        TDB_DEBUG_LOG("Warning: Failed to save config file for column family: %s", cf->name);
        return TDB_ERR_IO;
    }

    TDB_DEBUG_LOG("Updated configuration for column family: %s", cf->name);
    TDB_DEBUG_LOG("  memtable_flush_size: " TDB_SIZE_FMT,
                  TDB_SIZE_CAST(cf->config.memtable_flush_size));
    TDB_DEBUG_LOG("  max_sstables_before_compaction: %d",
                  cf->config.max_sstables_before_compaction);
    TDB_DEBUG_LOG("  compaction_threads: %d", cf->config.compaction_threads);
    TDB_DEBUG_LOG("  max_level: %d", cf->config.sl_max_level);
    TDB_DEBUG_LOG("  probability: %.2f", cf->config.sl_probability);
    TDB_DEBUG_LOG("  bloom_filter_fp_rate: %.4f", cf->config.bloom_filter_fp_rate);
    TDB_DEBUG_LOG("  enable_background_compaction: %d", cf->config.enable_background_compaction);
    TDB_DEBUG_LOG("  sync_mode: %d", cf->config.sync_mode);
    TDB_DEBUG_LOG("  background_compaction_interval: %d",
                  cf->config.background_compaction_interval);
    TDB_DEBUG_LOG("  block_manager_cache_size: %d", cf->config.block_manager_cache_size);
    TDB_DEBUG_LOG("  enable_bloom_filter: %d", cf->config.enable_bloom_filter);
    TDB_DEBUG_LOG("  bloom_filter_fp_rate: %.4f", cf->config.bloom_filter_fp_rate);
    TDB_DEBUG_LOG("  sync_mode: %d", cf->config.sync_mode);

    return 0;
}

int tidesdb_flush_memtable(tidesdb_column_family_t *cf)
{
    if (!cf) return TDB_ERR_INVALID_ARGS;

    TDB_DEBUG_LOG("Flushing memtable for column family: %s", cf->name);

    return tidesdb_rotate_memtable(cf);
}

int tidesdb_compact(tidesdb_column_family_t *cf)
{
    if (!cf) return TDB_ERR_INVALID_ARGS;

    if (cf->config.compaction_threads >= 2)
    {
        return tidesdb_compact_parallel(cf);
    }

    TDB_DEBUG_LOG("Starting single-threaded compaction for column family: %s (sstables: %d)",
                  cf->name, atomic_load(&cf->num_sstables));

    pthread_mutex_lock(&cf->compaction_lock);

    pthread_rwlock_rdlock(&cf->cf_lock);
    int num_ssts = atomic_load(&cf->num_sstables);
    if (num_ssts < 2)
    {
        pthread_rwlock_unlock(&cf->cf_lock);
        pthread_mutex_unlock(&cf->compaction_lock);
        return 0;
    }

    int pairs_to_merge = num_ssts / 2;
    tidesdb_sstable_t **sst_snapshot = malloc(num_ssts * sizeof(tidesdb_sstable_t *));
    if (!sst_snapshot)
    {
        pthread_rwlock_unlock(&cf->cf_lock);
        pthread_mutex_unlock(&cf->compaction_lock);
        return -1;
    }
    memcpy(sst_snapshot, cf->sstables, num_ssts * sizeof(tidesdb_sstable_t *));

    for (int i = 0; i < num_ssts; i++)
    {
        if (sst_snapshot[i])
        {
            tidesdb_sstable_acquire(sst_snapshot[i]);
        }
    }
    pthread_rwlock_unlock(&cf->cf_lock);

    /* release compaction lock -- merge doesn't need it, only array swap does */
    /* ref counts keep old sstables alive during merge */
    pthread_mutex_unlock(&cf->compaction_lock);

    tidesdb_sstable_t **merged_ssts = calloc((size_t)pairs_to_merge, sizeof(tidesdb_sstable_t *));
    if (!merged_ssts)
    {
        for (int i = 0; i < num_ssts; i++)
        {
            if (sst_snapshot[i])
            {
                tidesdb_sstable_release(sst_snapshot[i]);
            }
        }
        free(sst_snapshot);
        return -1;
    }

    for (int p = 0; p < pairs_to_merge; p++)
    {
        /* check if database is shutting down -- abort compaction early */
        if (cf->db->compaction_pool && atomic_load(&cf->db->compaction_pool->shutdown))
        {
            TDB_DEBUG_LOG("Shutdown detected, aborting compaction");
            break;
        }

        tidesdb_sstable_t *sst1 = sst_snapshot[p * 2];
        tidesdb_sstable_t *sst2 = sst_snapshot[p * 2 + 1];

        if (!sst1 || !sst2) continue;

        /* create new merged sstable with temp extension */
        uint64_t new_id = atomic_fetch_add(&cf->next_sstable_id, 1);
        /* just in case we check for overflow. this is safe because column families have a max
         * sstable count; old ids are expired */
        if (new_id == UINT64_MAX)
        {
            TDB_DEBUG_LOG("SSTable ID overflow for CF '%s', resetting to 0", cf->name);
            atomic_store(&cf->next_sstable_id, 0);
            new_id = 0;
        }

        char new_path[TDB_MAX_PATH_LENGTH];
        char temp_path[TDB_MAX_PATH_LENGTH];
        get_sstable_path(cf, new_id, new_path);
        (void)snprintf(temp_path, TDB_MAX_PATH_LENGTH, "%s%s", new_path, TDB_TEMP_EXT);

        TDB_DEBUG_LOG("Compacting sstables " TDB_U64_FMT " and " TDB_U64_FMT " into " TDB_U64_FMT
                      " (temp: %s)",
                      (unsigned long long)sst1->id, (unsigned long long)sst2->id,
                      (unsigned long long)new_id, temp_path);

        tidesdb_sstable_t *merged = malloc(sizeof(tidesdb_sstable_t));
        if (!merged) continue;

        merged->id = new_id;
        merged->cf = cf;
        merged->min_key = NULL;
        merged->max_key = NULL;
        merged->num_entries = 0;
        atomic_store(&merged->ref_count, 1);
        pthread_mutex_init(&merged->ref_lock, NULL);

        merged->block_manager = get_cached_block_manager(cf->db, temp_path, cf->config.sync_mode,
                                                         cf->config.block_manager_cache_size);
        if (!merged->block_manager)
        {
            free(merged);
            continue;
        }

        /* create bloom filter only if enabled */
        merged->bloom_filter = NULL;
        if (cf->config.enable_bloom_filter)
        {
            TDB_DEBUG_LOG("Creating bloom filter (entries: %d, fp_rate: %f)",
                          sst1->num_entries + sst2->num_entries, cf->config.bloom_filter_fp_rate);
            bloom_filter_new(&merged->bloom_filter, cf->config.bloom_filter_fp_rate,
                             sst1->num_entries + sst2->num_entries);
            if (merged->bloom_filter)
            {
                TDB_DEBUG_LOG("Bloom filter created successfully");
            }
        }

        merged->index = NULL; /* will be built after merging in second pass */

        /* merge entries from both sstables using cursors with key comparison */
        TDB_DEBUG_LOG("Creating block manager cursors for compaction merge");
        block_manager_cursor_t *cursor1 = NULL;
        block_manager_cursor_t *cursor2 = NULL;
        block_manager_cursor_init(&cursor1, sst1->block_manager);
        block_manager_cursor_init(&cursor2, sst2->block_manager);

        if (cursor1) block_manager_cursor_goto_first(cursor1);
        if (cursor2) block_manager_cursor_goto_first(cursor2);

        /* track blocks read to avoid reading metadata blocks */
        int blocks_read1 = 0;
        int blocks_read2 = 0;

        /* peek buffers for key comparison */
        block_manager_block_t *peek1 = NULL;
        block_manager_block_t *peek2 = NULL;

        uint8_t *key1 = NULL, *key2 = NULL;
        size_t key1_size = 0, key2_size = 0;
        uint8_t *decompressed1 = NULL; /* track decompressed data for cleanup */
        uint8_t *decompressed2 = NULL;

        /* initial peek from both cursors */
        int has1 = peek_next_block_for_merge(cursor1, &blocks_read1, sst1->num_entries, &peek1,
                                             &key1, &key1_size, &decompressed1, cf);
        int has2 = peek_next_block_for_merge(cursor2, &blocks_read2, sst2->num_entries, &peek2,
                                             &key2, &key2_size, &decompressed2, cf);

        skip_list_comparator_fn comparator = tidesdb_get_comparator(cf->comparator_name);

        while (has1 || has2)
        {
            block_manager_block_t *block = NULL;
            int use1 = 0;

            if (has1 && has2)
            {
                /* compare keys to decide which to use */
                int cmp = comparator(key1, key1_size, key2, key2_size, NULL);
                if (cmp < 0)
                {
                    /* key1 < key2, use sst1 */
                    use1 = 1;
                }
                else if (cmp > 0)
                {
                    /* key1 > key2, use sst2 */
                    use1 = 0;
                }
                else
                {
                    /* keys are equal, prefer sst2 (newer), skip sst1 */
                    if (decompressed1) free(decompressed1);
                    block_manager_block_free(peek1);
                    peek1 = NULL;
                    decompressed1 = NULL;
                    has1 = peek_next_block_for_merge(cursor1, &blocks_read1, sst1->num_entries,
                                                     &peek1, &key1, &key1_size, &decompressed1, cf);
                    use1 = 0; /* use sst2 */
                }
            }
            else if (has1)
            {
                use1 = 1;
            }
            else
            {
                use1 = 0;
            }

            if (use1)
            {
                block = peek1;
                peek1 = NULL;
                if (decompressed1)
                {
                    free(decompressed1);
                    decompressed1 = NULL;
                }
                has1 = peek_next_block_for_merge(cursor1, &blocks_read1, sst1->num_entries, &peek1,
                                                 &key1, &key1_size, &decompressed1, cf);
            }
            else
            {
                block = peek2;
                peek2 = NULL;
                if (decompressed2)
                {
                    free(decompressed2);
                    decompressed2 = NULL;
                }
                has2 = peek_next_block_for_merge(cursor2, &blocks_read2, sst2->num_entries, &peek2,
                                                 &key2, &key2_size, &decompressed2, cf);
            }

            if (block && block->data)
            {
                /* decompress if needed */
                uint8_t *data = block->data;
                size_t data_size = block->size;

                if (cf->config.enable_compression)
                {
                    size_t decompressed_size = 0;
                    uint8_t *decompressed = decompress_data(data, data_size, &decompressed_size,
                                                            cf->config.compression_algorithm);
                    if (decompressed)
                    {
                        data = decompressed;
                        data_size = decompressed_size;
                    }
                }

                /* parse key from block using new format */
                if (data_size < TDB_KV_HEADER_SIZE)
                {
                    if (data != block->data) free(data);
                    block_manager_block_free(block);
                    continue;
                }

                uint8_t version, flags;
                uint32_t key_size, value_size;
                int64_t ttl;
                deserialize_kv_header(data, &version, &flags, &key_size, &value_size, &ttl);

                /* skip tombstones during compaction */
                if (flags & TDB_KV_FLAG_TOMBSTONE)
                {
                    if (data != block->data) free(data);
                    block_manager_block_free(block);
                    continue;
                }

                /* skip expired entries during compaction */
                if (ttl > 0 && time(NULL) > ttl)
                {
                    if (data != block->data) free(data);
                    block_manager_block_free(block);
                    continue;
                }

                uint8_t *key = data + TDB_KV_HEADER_SIZE;
                size_t k_size = key_size;

                /* copy key to avoid use-after-free when data is freed */
                uint8_t *key_copy = malloc(k_size);
                if (!key_copy)
                {
                    if (data != block->data) free(data);
                    block_manager_block_free(block);
                    continue;
                }
                memcpy(key_copy, key, k_size);

                /* write to merged sstable */
                uint8_t *final_data = data;
                size_t final_size = data_size;

                if (cf->config.enable_compression)
                {
                    size_t compressed_size = 0;
                    uint8_t *compressed = compress_data(data, data_size, &compressed_size,
                                                        cf->config.compression_algorithm);
                    if (compressed)
                    {
                        if (data != block->data)
                        {
                            free(data);
                            data = NULL;
                        }
                        final_data = compressed;
                        final_size = compressed_size;
                    }
                }

                block_manager_block_t *new_block =
                    block_manager_block_create(final_size, final_data);
                if (new_block)
                {
                    long offset = block_manager_block_write(merged->block_manager, new_block);
                    if (offset >= 0)
                    {
                        if (merged->bloom_filter)
                        {
                            bloom_filter_add(merged->bloom_filter, key_copy, k_size);
                        }
                        merged->num_entries++;

                        if (!merged->min_key)
                        {
                            merged->min_key = malloc(k_size);
                            if (merged->min_key)
                            {
                                memcpy(merged->min_key, key_copy, k_size);
                                merged->min_key_size = k_size;
                            }
                        }

                        if (merged->max_key) free(merged->max_key);
                        merged->max_key = malloc(k_size);
                        if (merged->max_key)
                        {
                            memcpy(merged->max_key, key_copy, k_size);
                            merged->max_key_size = k_size;
                        }
                    }
                    block_manager_block_free(new_block);
                }

                free(key_copy);
                if (final_data != data && final_data != block->data) free(final_data);
                if (data && data != block->data) free(data);
                block_manager_block_free(block);
            }
        }

        if (decompressed1) free(decompressed1);
        if (decompressed2) free(decompressed2);
        if (peek1) block_manager_block_free(peek1);
        if (peek2) block_manager_block_free(peek2);

        if (cursor1) block_manager_cursor_free(cursor1);
        if (cursor2) block_manager_cursor_free(cursor2);

        /* build the succinct trie index by reading the merged sstable (two-pass approach) */
        /* this avoids keeping all decompressed data in memory during merge */
        if (tidesdb_build_sstable_index(merged, cf) != 0)
        {
            /* index build failed, but sstable is still valid -- continue without index */
            TDB_DEBUG_LOG("Failed to build index for merged SSTable");
        }

        /* write metadata (magic number, entry count, min/max keys) */
        if (merged->min_key && merged->max_key)
        {
            uint32_t magic = TDB_SST_META_MAGIC;
            size_t metadata_size = sizeof(uint32_t) + sizeof(uint64_t) + sizeof(uint32_t) +
                                   merged->min_key_size + sizeof(uint32_t) + merged->max_key_size;
            uint8_t *metadata = malloc(metadata_size);
            if (metadata)
            {
                uint8_t *ptr = metadata;
                encode_uint32_le(ptr, magic);
                ptr += sizeof(uint32_t);
                uint64_t num_entries = (uint64_t)merged->num_entries;
                encode_uint64_le(ptr, num_entries);
                ptr += sizeof(uint64_t);
                uint32_t min_size = (uint32_t)merged->min_key_size;
                encode_uint32_le(ptr, min_size);
                ptr += sizeof(uint32_t);
                memcpy(ptr, merged->min_key, merged->min_key_size);
                ptr += merged->min_key_size;
                uint32_t max_size = (uint32_t)merged->max_key_size;
                encode_uint32_le(ptr, max_size);
                ptr += sizeof(uint32_t);
                memcpy(ptr, merged->max_key, merged->max_key_size);

                block_manager_block_t *metadata_block =
                    block_manager_block_create(metadata_size, metadata);
                if (metadata_block)
                {
                    block_manager_block_write(merged->block_manager, metadata_block);
                    block_manager_block_free(metadata_block);
                }
                free(metadata);
            }
        }

        /* write bloom filter */
        if (merged->bloom_filter)
        {
            size_t bloom_size = 0;
            uint8_t *bloom_data = bloom_filter_serialize(merged->bloom_filter, &bloom_size);
            if (bloom_data)
            {
                block_manager_block_t *bloom_block =
                    block_manager_block_create(bloom_size, bloom_data);
                if (bloom_block)
                {
                    block_manager_block_write(merged->block_manager, bloom_block);
                    block_manager_block_free(bloom_block);
                }
                free(bloom_data);
            }
        }

        if (merged->index)
        {
            size_t index_size = 0;
            uint8_t *index_data = succinct_trie_serialize(merged->index, &index_size);
            if (index_data)
            {
                block_manager_block_t *index_block =
                    block_manager_block_create(index_size, index_data);
                if (index_block)
                {
                    block_manager_block_write(merged->block_manager, index_block);
                    block_manager_block_free(index_block);
                }
                free(index_data);
            }
        }

        /* remove temp file's block manager from cache and close it before rename */
        if (cf->db->block_manager_cache)
        {
            lru_cache_remove(cf->db->block_manager_cache, temp_path);
        }
        merged->block_manager = NULL;

        /* rename temp file to final name (atomic operation) */
        if (rename(temp_path, new_path) == 0)
        {
            TDB_DEBUG_LOG("Successfully renamed %s to %s", temp_path, new_path);
            /* reopen with final path via cache */
            merged->block_manager = get_cached_block_manager(cf->db, new_path, cf->config.sync_mode,
                                                             cf->config.block_manager_cache_size);
            if (!merged->block_manager)
            {
                TDB_DEBUG_LOG("Failed to reopen merged sstable after rename");
                tidesdb_sstable_free(merged);
                continue;
            }
        }
        else
        {
            TDB_DEBUG_LOG("Failed to rename %s to %s", temp_path, new_path);
            tidesdb_sstable_free(merged);
            continue;
        }

        /* store merged sstable for later array update */
        merged_ssts[p] = merged;
    }

    /* re-acquire compaction lock before modifying sstable array
     * compaction_lock serializes compactions without blocking readers */
    pthread_mutex_lock(&cf->compaction_lock);

    /* check if array was modified during compaction */
    int current_num_ssts = atomic_load(&cf->num_sstables);
    if (current_num_ssts != num_ssts)
    {
        TDB_DEBUG_LOG("SSTable array changed during compaction (%d -> %d), adjusting", num_ssts,
                      current_num_ssts);

        /* append merged sstables instead of replacing in-place */
        for (int p = 0; p < pairs_to_merge; p++)
        {
            tidesdb_sstable_t *merged = merged_ssts[p];
            if (!merged) continue;

            if (cf->num_sstables >= cf->sstable_array_capacity)
            {
                int new_cap = cf->sstable_array_capacity * 2;
                tidesdb_sstable_t **new_ssts =
                    realloc(cf->sstables, (size_t)new_cap * sizeof(tidesdb_sstable_t *));
                if (!new_ssts)
                {
                    tidesdb_sstable_free(merged);
                    merged_ssts[p] = NULL;
                    continue;
                }
                cf->sstables = new_ssts;
                cf->sstable_array_capacity = new_cap;
            }

            /* add merged sstable to end */
            cf->sstables[cf->num_sstables] = merged;
            atomic_fetch_add(&cf->num_sstables, 1);
        }

        /* now mark old sstables for deletion */
        for (int p = 0; p < pairs_to_merge; p++)
        {
            tidesdb_sstable_t *sst1 = sst_snapshot[p * 2];
            tidesdb_sstable_t *sst2 = sst_snapshot[p * 2 + 1];

            for (int i = 0; i < atomic_load(&cf->num_sstables); i++)
            {
                if (cf->sstables[i] == sst1 || cf->sstables[i] == sst2)
                {
                    if (cf->sstables[i] == sst1)
                    {
                        tidesdb_sstable_release(sst1);
                    }
                    else
                    {
                        tidesdb_sstable_release(sst2);
                    }
                    cf->sstables[i] = NULL;
                }
            }
        }

        /* compact array */
        int new_count = 0;
        for (int i = 0; i < atomic_load(&cf->num_sstables); i++)
        {
            if (cf->sstables[i])
            {
                cf->sstables[new_count++] = cf->sstables[i];
            }
        }
        atomic_store(&cf->num_sstables, new_count);
    }
    else
    {
        /* no modifications its safe to update in place */
        for (int p = 0; p < pairs_to_merge; p++)
        {
            tidesdb_sstable_t *sst1 = sst_snapshot[p * 2];
            tidesdb_sstable_t *sst2 = sst_snapshot[p * 2 + 1];
            tidesdb_sstable_t *merged = merged_ssts[p];

            if (!merged) continue;

            cf->sstables[p * 2] = merged;
            cf->sstables[p * 2 + 1] = NULL;

            if (sst1) tidesdb_sstable_release(sst1);
            if (sst2) tidesdb_sstable_release(sst2);
        }

        /* compact array to remove NULLs */
        int new_count = 0;
        for (int i = 0; i < num_ssts; i++)
        {
            if (cf->sstables[i])
            {
                cf->sstables[new_count++] = cf->sstables[i];
            }
        }
        atomic_store(&cf->num_sstables, new_count);
    }

    pthread_mutex_unlock(&cf->compaction_lock);

    /* release snapshot references */
    TDB_DEBUG_LOG("Releasing %d snapshot references", num_ssts);
    for (int i = 0; i < num_ssts; i++)
    {
        if (sst_snapshot[i])
        {
            uint64_t sst_id = sst_snapshot[i]->id;
            int ref_count_before = atomic_load(&sst_snapshot[i]->ref_count);
            TDB_DEBUG_LOG("Releasing snapshot SSTable %" PRIu64 ", ref_count before release: %d",
                          sst_id, ref_count_before);
            int remaining_refs = tidesdb_sstable_release(sst_snapshot[i]);
            TDB_DEBUG_LOG("Snapshot SSTable %" PRIu64 " released, remaining refs: %d", sst_id,
                          remaining_refs);
        }
    }

    free(sst_snapshot);
    free(merged_ssts);

    TDB_DEBUG_LOG(
        "Compaction completed for column family: %s (merged %d pairs, final sstables: %d)",
        cf->name, pairs_to_merge, atomic_load(&cf->num_sstables));

    return 0;
}

/*
 * peek_next_block_for_merge
 * helper function to read and extract key from next block during compaction merge
 * @param cursor block manager cursor
 * @param blocks_read pointer to blocks read counter
 * @param max_blocks maximum blocks to read
 * @param peek_block pointer to store peeked block
 * @param peek_key pointer to store key pointer
 * @param peek_key_size pointer to store key size
 * @param decompressed_ptr pointer to store decompressed data for cleanup
 * @param cf column family (for compression config)
 * @return 1 if block was read, 0 otherwise
 */
static int peek_next_block_for_merge(block_manager_cursor_t *cursor, int *blocks_read,
                                     int max_blocks, block_manager_block_t **peek_block,
                                     uint8_t **peek_key, size_t *peek_key_size,
                                     uint8_t **decompressed_ptr, tidesdb_column_family_t *cf)
{
    if (*blocks_read >= max_blocks) return 0;
    if (!block_manager_cursor_has_next(cursor)) return 0;

    *peek_block = block_manager_cursor_read(cursor);
    if (!*peek_block || !(*peek_block)->data) return 0;

    uint8_t *data = (*peek_block)->data;
    size_t data_size = (*peek_block)->size;

    if (*decompressed_ptr)
    {
        free(*decompressed_ptr);
        *decompressed_ptr = NULL;
    }

    /* decompress if needed for key extraction */
    if (cf->config.enable_compression)
    {
        size_t decompressed_size = 0;
        uint8_t *decompressed =
            decompress_data(data, data_size, &decompressed_size, cf->config.compression_algorithm);
        if (decompressed)
        {
            data = decompressed;
            data_size = decompressed_size;
            *decompressed_ptr = decompressed; /* track for cleanup */
        }
        else
        {
            *decompressed_ptr = NULL;
        }
    }
    else
    {
        *decompressed_ptr = NULL;
    }

    if (data_size < sizeof(tidesdb_kv_pair_header_t))
    {
        if (*decompressed_ptr) free(*decompressed_ptr);
        block_manager_block_free(*peek_block);
        *peek_block = NULL;
        return 0;
    }

    uint8_t version, flags;
    uint32_t key_size, value_size;
    int64_t ttl;
    deserialize_kv_header(data, &version, &flags, &key_size, &value_size, &ttl);

    /* validate key/value sizes to protect against corrupted data */
    int validation_result = tidesdb_validate_kv_size(cf->db, key_size, value_size);
    if (validation_result != 0)
    {
        TDB_DEBUG_LOG("Skipping corrupted block during compaction: key_size=%u, value_size=%u",
                      key_size, value_size);
        if (*decompressed_ptr) free(*decompressed_ptr);
        block_manager_block_free(*peek_block);
        *peek_block = NULL;
        return 0;
    }

    /* verify we have enough data for the key */
    if (data_size < TDB_KV_HEADER_SIZE + key_size)
    {
        TDB_DEBUG_LOG("Block data size (" TDB_SIZE_FMT ") insufficient for key size (%u)",
                      TDB_SIZE_CAST(data_size), key_size);
        if (*decompressed_ptr) free(*decompressed_ptr);
        block_manager_block_free(*peek_block);
        *peek_block = NULL;
        return 0;
    }

    *peek_key = data + TDB_KV_HEADER_SIZE;
    *peek_key_size = key_size;

    block_manager_cursor_next(cursor);
    (*blocks_read)++;
    return 1;
}

/*
 * compaction_job_t
 * @param cf column family
 * @param sst1 first sstable
 * @param sst2 second sstable
 * @param result pointer to store merged sstable
 * @param semaphore semaphore for thread synchronization
 * @param error pointer to store error code
 * @param acquired_refs number of acquired references to release
 */
typedef struct
{
    tidesdb_column_family_t *cf;
    tidesdb_sstable_t *sst1;
    tidesdb_sstable_t *sst2;
    tidesdb_sstable_t **result;
    sem_t *semaphore;
    int *error;
    int acquired_refs;
} compaction_job_t;

/*
 * tidesdb_compaction_worker
 * worker thread function for parallel compaction
 * @param arg pointer to compaction job
 */
static void *tidesdb_compaction_worker(void *arg)
{
    compaction_job_t *job = (compaction_job_t *)arg;
    tidesdb_column_family_t *cf = job->cf;

    if (atomic_load(&cf->is_dropping))
    {
        *job->error = 1;
        sem_post(job->semaphore);
        return NULL;
    }

    tidesdb_sstable_t *sst1 = job->sst1;
    tidesdb_sstable_t *sst2 = job->sst2;

    if (!sst1 || !sst2)
    {
        *job->error = 1;
        sem_post(job->semaphore);
        return NULL;
    }

    /* references already acquired by parent thread in tidesdb_compact_parallel */
    job->acquired_refs = 1;

    uint64_t new_id = atomic_fetch_add(&cf->next_sstable_id, 1);
    if (new_id == UINT64_MAX)
    {
        TDB_DEBUG_LOG("SSTable ID overflow for CF '%s', resetting to 0", cf->name);
        atomic_store(&cf->next_sstable_id, 0);
        new_id = 0;
    }

    char new_path[TDB_MAX_PATH_LENGTH];
    char temp_path[TDB_MAX_PATH_LENGTH];
    get_sstable_path(cf, new_id, new_path);
    (void)snprintf(temp_path, TDB_MAX_PATH_LENGTH, "%s%s", new_path, TDB_TEMP_EXT);

    TDB_DEBUG_LOG(
        "[Thread] Compacting sstables " TDB_U64_FMT " and " TDB_U64_FMT " into " TDB_U64_FMT,
        (unsigned long long)sst1->id, (unsigned long long)sst2->id, (unsigned long long)new_id);

    tidesdb_sstable_t *merged = malloc(sizeof(tidesdb_sstable_t));
    if (!merged)
    {
        *job->error = 1;

        tidesdb_sstable_release(sst1);
        tidesdb_sstable_release(sst2);
        sem_post(job->semaphore);
        return NULL;
    }

    merged->id = new_id;
    merged->cf = cf;
    merged->min_key = NULL;
    merged->max_key = NULL;
    merged->num_entries = 0;
    atomic_store(&merged->ref_count, 1);
    pthread_mutex_init(&merged->ref_lock, NULL);

    merged->block_manager = get_cached_block_manager(cf->db, temp_path, cf->config.sync_mode,
                                                     cf->config.block_manager_cache_size);
    if (!merged->block_manager)
    {
        pthread_mutex_destroy(&merged->ref_lock);
        free(merged);
        *job->error = 1;
        tidesdb_sstable_release(sst1);
        tidesdb_sstable_release(sst2);
        sem_post(job->semaphore);
        return NULL;
    }

    /* create bloom filter only if enabled */
    merged->bloom_filter = NULL;
    if (cf->config.enable_bloom_filter)
    {
        bloom_filter_new(&merged->bloom_filter, cf->config.bloom_filter_fp_rate,
                         sst1->num_entries + sst2->num_entries);
        if (!merged->bloom_filter)
        {
            if (cf->db->block_manager_cache)
            {
                lru_cache_remove(cf->db->block_manager_cache, temp_path);
            }
            if (merged->bloom_filter) bloom_filter_free(merged->bloom_filter);
            pthread_mutex_destroy(&merged->ref_lock);
            free(merged);
            *job->error = 1;
            tidesdb_sstable_release(sst1);
            tidesdb_sstable_release(sst2);
            sem_post(job->semaphore);
            return NULL;
        }
    }

    merged->index = NULL; /* will be built after merging in second pass */

    block_manager_cursor_t *cursor1 = NULL;
    block_manager_cursor_t *cursor2 = NULL;
    block_manager_cursor_init(&cursor1, sst1->block_manager);
    block_manager_cursor_init(&cursor2, sst2->block_manager);

    if (cursor1) block_manager_cursor_goto_first(cursor1);
    if (cursor2) block_manager_cursor_goto_first(cursor2);

    int blocks_read1 = 0;
    int blocks_read2 = 0;

    block_manager_block_t *peek1 = NULL;
    block_manager_block_t *peek2 = NULL;
    uint8_t *key1 = NULL, *key2 = NULL;
    size_t key1_size = 0, key2_size = 0;
    uint8_t *decompressed1 = NULL;
    uint8_t *decompressed2 = NULL;

    int has1 = peek_next_block_for_merge(cursor1, &blocks_read1, sst1->num_entries, &peek1, &key1,
                                         &key1_size, &decompressed1, cf);
    int has2 = peek_next_block_for_merge(cursor2, &blocks_read2, sst2->num_entries, &peek2, &key2,
                                         &key2_size, &decompressed2, cf);

    skip_list_comparator_fn comparator = tidesdb_get_comparator(cf->comparator_name);

    int merge_failed = 0;

    while ((has1 || has2) && !merge_failed)
    {
        block_manager_block_t *block = NULL;
        int use1 = 0;

        if (has1 && has2)
        {
            int cmp = comparator(key1, key1_size, key2, key2_size, NULL);
            if (cmp < 0)
            {
                use1 = 1;
            }
            else if (cmp > 0)
            {
                use1 = 0;
            }
            else
            {
                /* keys equal, prefer sst2 (newer), skip sst1 */
                if (decompressed1)
                {
                    free(decompressed1);
                    decompressed1 = NULL;
                }
                if (peek1)
                {
                    block_manager_block_free(peek1);
                    peek1 = NULL;
                }
                has1 = peek_next_block_for_merge(cursor1, &blocks_read1, sst1->num_entries, &peek1,
                                                 &key1, &key1_size, &decompressed1, cf);
                use1 = 0;
            }
        }
        else if (has1)
        {
            use1 = 1;
        }
        else
        {
            use1 = 0;
        }

        if (use1)
        {
            block = peek1;
            peek1 = NULL;
            has1 = peek_next_block_for_merge(cursor1, &blocks_read1, sst1->num_entries, &peek1,
                                             &key1, &key1_size, &decompressed1, cf);
        }
        else
        {
            block = peek2;
            peek2 = NULL;
            has2 = peek_next_block_for_merge(cursor2, &blocks_read2, sst2->num_entries, &peek2,
                                             &key2, &key2_size, &decompressed2, cf);
        }

        if (block && block->data)
        {
            uint8_t *data = block->data;
            size_t data_size = block->size;

            if (cf->config.enable_compression)
            {
                size_t decompressed_size = 0;
                uint8_t *decompressed = decompress_data(data, data_size, &decompressed_size,
                                                        cf->config.compression_algorithm);
                if (decompressed)
                {
                    data = decompressed;
                    data_size = decompressed_size;
                }
            }

            if (data_size >= TDB_KV_HEADER_SIZE)
            {
                uint8_t version, flags;
                uint32_t key_size, value_size;
                int64_t ttl;
                deserialize_kv_header(data, &version, &flags, &key_size, &value_size, &ttl);

                uint8_t *ptr = data + TDB_KV_HEADER_SIZE;
                uint8_t *block_key = ptr;

                /* check if deleted or expired */
                int is_deleted = (flags & TDB_KV_FLAG_TOMBSTONE) != 0;
                int is_expired = (ttl > 0 && time(NULL) > ttl);

                if (is_deleted || is_expired)
                {
                    if (data != block->data) free(data);
                    block_manager_block_free(block);
                    continue;
                }

                /* allocate and copy value */
                uint8_t *final_data = data;
                size_t final_size = data_size;

                if (cf->config.enable_compression)
                {
                    size_t compressed_size = 0;
                    uint8_t *compressed = compress_data(data, data_size, &compressed_size,
                                                        cf->config.compression_algorithm);
                    if (compressed)
                    {
                        final_data = compressed;
                        final_size = compressed_size;
                    }
                }

                block_manager_block_t *new_block =
                    block_manager_block_create(final_size, final_data);
                if (new_block)
                {
                    long offset = block_manager_block_write(merged->block_manager, new_block);
                    if (offset >= 0)
                    {
                        if (merged->bloom_filter)
                        {
                            bloom_filter_add(merged->bloom_filter, block_key, key_size);
                        }
                        merged->num_entries++;

                        if (!merged->min_key)
                        {
                            merged->min_key = malloc(key_size);
                            if (merged->min_key)
                            {
                                memcpy(merged->min_key, block_key, key_size);
                                merged->min_key_size = key_size;
                            }
                        }

                        if (merged->max_key) free(merged->max_key);
                        merged->max_key = malloc(key_size);
                        if (merged->max_key)
                        {
                            memcpy(merged->max_key, block_key, key_size);
                            merged->max_key_size = key_size;
                        }
                    }
                    block_manager_block_free(new_block);
                }

                if (cf->config.enable_compression && final_data != data)
                {
                    free(final_data);
                }
            }

            if (cf->config.enable_compression && data != block->data)
            {
                free(data);
            }
            block_manager_block_free(block);
        }
    }

    if (decompressed1) free(decompressed1);
    if (decompressed2) free(decompressed2);
    if (peek1) block_manager_block_free(peek1);
    if (peek2) block_manager_block_free(peek2);
    if (cursor1) block_manager_cursor_free(cursor1);
    if (cursor2) block_manager_cursor_free(cursor2);

    tidesdb_sstable_release(sst1);
    tidesdb_sstable_release(sst2);

    if (merge_failed)
    {
        if (cf->db->block_manager_cache)
        {
            lru_cache_remove(cf->db->block_manager_cache, temp_path);
        }
        if (merged->bloom_filter) bloom_filter_free(merged->bloom_filter);
        if (merged->index) succinct_trie_free(merged->index);
        if (merged->min_key) free(merged->min_key);
        if (merged->max_key) free(merged->max_key);
        pthread_mutex_destroy(&merged->ref_lock);
        free(merged);
        remove(temp_path);
        *job->error = 1;
        sem_post(job->semaphore);
        return NULL;
    }

    /* build the succinct trie index by reading the merged sstable (two-pass approach) */
    /* this avoids keeping all decompressed data in memory during merge */
    if (tidesdb_build_sstable_index(merged, cf) != 0)
    {
        /* index build failed, but sstable is still valid -- continue without index */
        TDB_DEBUG_LOG("Failed to build index for merged SSTable");
    }

    /* write metadata */
    if (merged->min_key && merged->max_key)
    {
        uint32_t magic = TDB_SST_META_MAGIC;
        size_t metadata_size = sizeof(uint32_t) + sizeof(uint64_t) + sizeof(uint32_t) +
                               merged->min_key_size + sizeof(uint32_t) + merged->max_key_size;
        uint8_t *metadata = malloc(metadata_size);
        if (metadata)
        {
            uint8_t *ptr = metadata;
            encode_uint32_le(ptr, magic);
            ptr += sizeof(uint32_t);
            uint64_t num_entries = (uint64_t)merged->num_entries;
            encode_uint64_le(ptr, num_entries);
            ptr += sizeof(uint64_t);
            uint32_t min_size = (uint32_t)merged->min_key_size;
            encode_uint32_le(ptr, min_size);
            ptr += sizeof(uint32_t);
            memcpy(ptr, merged->min_key, merged->min_key_size);
            ptr += merged->min_key_size;
            uint32_t max_size = (uint32_t)merged->max_key_size;
            encode_uint32_le(ptr, max_size);
            ptr += sizeof(uint32_t);
            memcpy(ptr, merged->max_key, merged->max_key_size);

            block_manager_block_t *metadata_block =
                block_manager_block_create(metadata_size, metadata);
            if (metadata_block)
            {
                block_manager_block_write(merged->block_manager, metadata_block);
                block_manager_block_free(metadata_block);
            }
            free(metadata);
        }
    }

    /* write bloom filter and index */
    if (merged->bloom_filter)
    {
        size_t bloom_size = 0;
        uint8_t *bloom_data = bloom_filter_serialize(merged->bloom_filter, &bloom_size);
        if (bloom_data)
        {
            block_manager_block_t *bloom_block = block_manager_block_create(bloom_size, bloom_data);
            if (bloom_block)
            {
                block_manager_block_write(merged->block_manager, bloom_block);
                block_manager_block_free(bloom_block);
            }
            free(bloom_data);
        }
    }

    if (merged->index)
    {
        size_t index_size = 0;
        uint8_t *index_data = succinct_trie_serialize(merged->index, &index_size);
        if (index_data)
        {
            block_manager_block_t *index_block = block_manager_block_create(index_size, index_data);
            if (index_block)
            {
                block_manager_block_write(merged->block_manager, index_block);
                block_manager_block_free(index_block);
            }
            free(index_data);
        }
    }

    /* remove temp file's block manager from cache and close it before rename */
    if (cf->db->block_manager_cache)
    {
        lru_cache_remove(cf->db->block_manager_cache, temp_path);
    }
    merged->block_manager = NULL;

    /* rename temp to final */
    if (rename(temp_path, new_path) == 0)
    {
        merged->block_manager = get_cached_block_manager(cf->db, new_path, cf->config.sync_mode,
                                                         cf->config.block_manager_cache_size);
        if (merged->block_manager)
        {
            *job->result = merged;
        }
        else
        {
            tidesdb_sstable_free(merged);
            *job->error = 1;
        }
    }
    else
    {
        tidesdb_sstable_free(merged);
        *job->error = 1;
    }

    *job->result = merged;
    sem_post(job->semaphore);
    return NULL;
}

int tidesdb_compact_parallel(tidesdb_column_family_t *cf)
{
    if (!cf) return TDB_ERR_INVALID_ARGS;

    TDB_DEBUG_LOG("Starting parallel compaction for column family: %s (sstables: %d, threads: %d)",
                  cf->name, atomic_load(&cf->num_sstables), cf->config.compaction_threads);

    pthread_mutex_lock(&cf->compaction_lock);
    pthread_rwlock_rdlock(&cf->cf_lock);

    int num_ssts = atomic_load(&cf->num_sstables);
    if (num_ssts < 2)
    {
        pthread_rwlock_unlock(&cf->cf_lock);
        pthread_mutex_unlock(&cf->compaction_lock);
        return 0;
    }

    int pairs_to_merge = num_ssts / 2;
    int num_threads = cf->config.compaction_threads;
    if (num_threads > pairs_to_merge) num_threads = pairs_to_merge;

    sem_t semaphore = {0};
    if (sem_init(&semaphore, 0, (unsigned int)num_threads) != 0)
    {
        pthread_rwlock_unlock(&cf->cf_lock);
        pthread_mutex_unlock(&cf->compaction_lock);
        return -1;
    }

    /* allocate arrays for jobs, threads, and results */
    compaction_job_t *jobs = calloc((size_t)pairs_to_merge, sizeof(compaction_job_t));
    pthread_t *threads = calloc((size_t)pairs_to_merge, sizeof(pthread_t));
    tidesdb_sstable_t **merged_sstables =
        calloc((size_t)pairs_to_merge, sizeof(tidesdb_sstable_t *));
    int *errors = calloc((size_t)pairs_to_merge, sizeof(int));
    int *thread_created = calloc((size_t)pairs_to_merge, sizeof(int)); /* track created threads */

    if (!jobs || !threads || !merged_sstables || !errors || !thread_created)
    {
        free(jobs);
        free(threads);
        free(merged_sstables);
        free(errors);
        free(thread_created);
        sem_destroy(&semaphore);
        pthread_rwlock_unlock(&cf->cf_lock);
        pthread_mutex_unlock(&cf->compaction_lock);
        return -1;
    }

    /* snapshot sstable pointers and acquire references while holding lock
     * this prevents use-after-free if sstables are modified by another thread */
    for (int p = 0; p < pairs_to_merge; p++)
    {
        jobs[p].sst1 = cf->sstables[p * 2];
        jobs[p].sst2 = cf->sstables[p * 2 + 1];

        /* acquire references immediately to prevent sstables from being freed */
        if (jobs[p].sst1) tidesdb_sstable_acquire(jobs[p].sst1);
        if (jobs[p].sst2) tidesdb_sstable_acquire(jobs[p].sst2);
    }

    /* release read lock -- compaction can proceed without blocking reads
     * we've already acquired references to all sstables we need */
    pthread_rwlock_unlock(&cf->cf_lock);

    /* launch worker threads for each pair */
    for (int p = 0; p < pairs_to_merge; p++)
    {
        /* check if database is shutting down -- abort compaction early */
        if (cf->db->compaction_pool && atomic_load(&cf->db->compaction_pool->shutdown))
        {
            TDB_DEBUG_LOG("Shutdown detected, aborting parallel compaction");
            /* release references we acquired and semaphore for any waiting threads */
            for (int i = p; i < pairs_to_merge; i++)
            {
                if (jobs[i].sst1) tidesdb_sstable_release(jobs[i].sst1);
                if (jobs[i].sst2) tidesdb_sstable_release(jobs[i].sst2);
            }
            sem_post(&semaphore);
            break;
        }

        sem_wait(&semaphore);

        jobs[p].cf = cf;
        /* sst1 and sst2 already set and acquired above */
        jobs[p].result = &merged_sstables[p];
        jobs[p].semaphore = &semaphore;
        jobs[p].error = &errors[p];

        if (pthread_create(&threads[p], NULL, tidesdb_compaction_worker, &jobs[p]) != 0)
        {
            /* thread creation failed, mark as error, release references and semaphore */
            errors[p] = 1;
            thread_created[p] = 0;
            if (jobs[p].sst1) tidesdb_sstable_release(jobs[p].sst1);
            if (jobs[p].sst2) tidesdb_sstable_release(jobs[p].sst2);
            sem_post(&semaphore);
            TDB_DEBUG_LOG("Failed to create compaction thread for pair %d", p);
        }
        else
        {
            thread_created[p] = 1;
        }
    }

    /* wait for all threads to complete */
    for (int p = 0; p < pairs_to_merge; p++)
    {
        if (thread_created[p])
        {
            pthread_join(threads[p], NULL);
        }
    }

    /* compaction_lock already held from beginning of function */
    /* rebuild sstable array; must keep originals if merge failed */
    tidesdb_sstable_t **new_sstables =
        malloc((size_t)(num_ssts + pairs_to_merge) * sizeof(tidesdb_sstable_t *));
    int new_count = 0;

    for (int p = 0; p < pairs_to_merge; p++)
    {
        if (!errors[p] && merged_sstables[p])
        {
            /* merge succeeded, now we can add merged sstable and release originals */
            new_sstables[new_count++] = merged_sstables[p];

            /* use snapshot from jobs, not current cf->sstables which may have changed */
            tidesdb_sstable_t *sst1 = jobs[p].sst1;
            tidesdb_sstable_t *sst2 = jobs[p].sst2;

            /* delete old sstable files */
            char sst1_path[TDB_MAX_PATH_LENGTH];
            char sst2_path[TDB_MAX_PATH_LENGTH];
            get_sstable_path(cf, sst1->id, sst1_path);
            get_sstable_path(cf, sst2->id, sst2_path);

            tidesdb_sstable_release(sst1);
            tidesdb_sstable_release(sst2);

            remove(sst1_path);
            remove(sst2_path);
        }
        else
        {
            /* merge failed, keep both original sstables. */
            new_sstables[new_count++] = cf->sstables[p * 2];
            new_sstables[new_count++] = cf->sstables[p * 2 + 1];
        }
    }

    /* add odd sstable if exists */
    if (num_ssts % 2 == 1)
    {
        new_sstables[new_count++] = cf->sstables[num_ssts - 1];
    }

    free(cf->sstables);
    cf->sstables = new_sstables;
    cf->sstable_array_capacity = num_ssts + pairs_to_merge; /* update capacity */
    atomic_store(&cf->num_sstables, new_count);

    free(jobs);
    free(threads);
    free(merged_sstables);
    free(errors);
    free(thread_created);
    sem_destroy(&semaphore);

    pthread_mutex_unlock(&cf->compaction_lock);

    TDB_DEBUG_LOG("Parallel compaction complete: %d -> %d sstables", num_ssts, new_count);
    return 0;
}

/*
 * tidesdb_check_and_flush
 * checks if memtable or WAL exceeds flush threshold and flushes if necessary
 * @param cf column family to check
 * @return 0 on success, -1 on failure
 */
static int tidesdb_check_and_flush(tidesdb_column_family_t *cf)
{
    if (!cf) return TDB_ERR_INVALID_ARGS;

    tidesdb_memtable_t *active_mt = atomic_load(&cf->active_memtable);
    if (!active_mt) return TDB_ERR_INVALID_ARGS;

    tidesdb_memtable_acquire(active_mt);
    size_t memtable_size = (size_t)skip_list_get_size(active_mt->memtable);
    size_t wal_size = 0;
    if (active_mt->wal)
    {
        uint64_t size;
        if (block_manager_get_size(active_mt->wal, &size) == 0)
        {
            wal_size = (size_t)size;
        }
    }
    tidesdb_memtable_release(active_mt);

    /* flush if EITHER memtable OR WAL exceeds threshold */
    if (memtable_size >= cf->config.memtable_flush_size ||
        wal_size >= cf->config.memtable_flush_size)
    {
        TDB_DEBUG_LOG(
            "Triggering memtable rotation for CF '%s' (memtable: %zu, WAL: %zu, threshold: %zu)",
            cf->name, memtable_size, wal_size, cf->config.memtable_flush_size);
        return tidesdb_rotate_memtable(cf);
    }

    return 0;
}

/*
 * tidesdb_load_sstable
 * loads an sstable from disk
 * @param cf column family
 * @param sstable_id ID of sstable to load
 * @param sstable pointer to store loaded sstable
 * @return 0 on success, -1 on failure
 */
static int tidesdb_load_sstable(tidesdb_column_family_t *cf, uint64_t sstable_id,
                                tidesdb_sstable_t **sstable)
{
    if (!cf || !sstable) return TDB_ERR_INVALID_ARGS;

    char path[TDB_MAX_PATH_LENGTH];
    get_sstable_path(cf, sstable_id, path);

    tidesdb_sstable_t *sst = malloc(sizeof(tidesdb_sstable_t));
    if (!sst) return TDB_ERR_MEMORY;

    sst->id = sstable_id;
    sst->cf = cf;
    sst->min_key = NULL;
    sst->max_key = NULL;
    sst->num_entries = 0;
    sst->bloom_filter = NULL;
    sst->index = NULL;
    atomic_store(&sst->ref_count, 1);
    pthread_mutex_init(&sst->ref_lock, NULL);

    sst->block_manager = get_cached_block_manager(cf->db, path, cf->config.sync_mode,
                                                  cf->config.block_manager_cache_size);
    if (!sst->block_manager)
    {
        free(sst);
        return TDB_ERR_IO;
    }

    /* load metadata, index, and bloom filter from last blocks */
    block_manager_cursor_t *cursor = NULL;
    if (block_manager_cursor_init(&cursor, sst->block_manager) == 0)
    {
        block_manager_cursor_goto_last(cursor);

        /* try to read metadata (last block); check for magic number */
        block_manager_block_t *metadata_block = block_manager_cursor_read(cursor);
        int has_metadata = 0;
        if (metadata_block && metadata_block->data &&
            metadata_block->size >= sizeof(uint32_t) + sizeof(uint64_t) + 2 * sizeof(uint32_t))
        {
            uint8_t *ptr = metadata_block->data;
            uint32_t magic = decode_uint32_le(ptr);

            if (magic == TDB_SST_META_MAGIC)
            {
                ptr += sizeof(uint32_t);
                uint64_t num_entries = decode_uint64_le(ptr);
                ptr += sizeof(uint64_t);
                uint32_t min_key_size = decode_uint32_le(ptr);
                ptr += sizeof(uint32_t);

                sst->num_entries = (int)num_entries;
                sst->min_key = malloc(min_key_size);
                if (sst->min_key)
                {
                    memcpy(sst->min_key, ptr, min_key_size);
                    sst->min_key_size = min_key_size;
                }
                ptr += min_key_size;
                uint32_t max_key_size = decode_uint32_le(ptr);
                ptr += sizeof(uint32_t);
                sst->max_key = malloc(max_key_size);
                if (sst->max_key)
                {
                    memcpy(sst->max_key, ptr, max_key_size);
                    sst->max_key_size = max_key_size;
                }
                has_metadata = 1;
            }
        }
        if (metadata_block) block_manager_block_free(metadata_block);

        /* read index */
        if (has_metadata)
        {
            block_manager_cursor_prev(cursor);
        }
        block_manager_block_t *index_block = block_manager_cursor_read(cursor);
        if (index_block && index_block->data)
        {
            sst->index = succinct_trie_deserialize(index_block->data, index_block->size);
            block_manager_block_free(index_block);
        }

        /* read bloom filter */
        block_manager_cursor_prev(cursor);
        block_manager_block_t *bloom_block = block_manager_cursor_read(cursor);
        if (bloom_block && bloom_block->data)
        {
            sst->bloom_filter = bloom_filter_deserialize(bloom_block->data);
            block_manager_block_free(bloom_block);
        }

        block_manager_cursor_free(cursor);
    }

    *sstable = sst;
    return 0;
}

/*
 * tidesdb_sstable_get
 * gets a value from an sstable
 * @param sstable sstable to get from
 * @param key key to get
 * @param key_size size of key
 * @param value pointer to store value
 * @param value_size pointer to store value size
 * @return 0 on success, TDB_ERR_CORRUPT if data is corrupted, TDB_ERR_NOT_FOUND if key not found or
 * expired, -1 on other failures
 */
static int tidesdb_sstable_get(tidesdb_sstable_t *sstable, const uint8_t *key, size_t key_size,
                               uint8_t **value, size_t *value_size)
{
    if (!sstable || !key || !value || !value_size) return -1;

    /* we check if key is within sst's min/max range */
    if (sstable->min_key && sstable->max_key)
    {
        skip_list_comparator_fn cmp = tidesdb_get_comparator(sstable->cf->comparator_name);

        if (cmp(key, key_size, sstable->min_key, sstable->min_key_size, NULL) < 0) return -1;
        if (cmp(key, key_size, sstable->max_key, sstable->max_key_size, NULL) > 0) return -1;
    }

    /* check bloom filter first */
    if (sstable->bloom_filter && !bloom_filter_contains(sstable->bloom_filter, key, key_size))
    {
        return -1; /* definitely not in sstable */
    }

    int64_t block_offset = -1;

    /* if block indexes are enabled, use succinct trie for direct lookup */
    if (sstable->cf->config.enable_block_indexes && sstable->index)
    {
        if (succinct_trie_prefix_get(sstable->index, (uint8_t *)key, key_size, &block_offset) != 0)
        {
            return -1; /* not found in index */
        }
    }
    else
    {
        /* fallback is linear scan through blocks */
        block_manager_cursor_t *cursor = NULL;
        if (block_manager_cursor_init(&cursor, sstable->block_manager) != 0) return -1;

        block_manager_cursor_goto_first(cursor);

        while (block_manager_cursor_has_next(cursor))
        {
            block_manager_block_t *block = block_manager_cursor_read(cursor);
            if (block && block->data)
            {
                /* decompress if needed */
                uint8_t *data = block->data;
                size_t data_size = block->size;

                if (sstable->cf->config.enable_compression)
                {
                    size_t decompressed_size = 0;
                    uint8_t *decompressed =
                        decompress_data(data, data_size, &decompressed_size,
                                        sstable->cf->config.compression_algorithm);
                    if (decompressed)
                    {
                        data = decompressed;
                        data_size = decompressed_size;
                    }
                }

                /* parse block using [header][key][value] */
                if (data_size < TDB_KV_HEADER_SIZE)
                {
                    if (data != block->data) free(data);
                    block_manager_block_free(block);
                    continue;
                }

                uint8_t hdr_version, hdr_flags;
                uint32_t hdr_key_size, hdr_value_size;
                int64_t hdr_ttl;
                deserialize_kv_header(data, &hdr_version, &hdr_flags, &hdr_key_size,
                                      &hdr_value_size, &hdr_ttl);

                uint8_t *ptr = data + TDB_KV_HEADER_SIZE;
                uint8_t *block_key = ptr;
                ptr += hdr_key_size;
                uint8_t *block_value = ptr;

                if (key_size == hdr_key_size && memcmp(block_key, key, key_size) == 0)
                {
                    /* check if deleted or expired */
                    int is_deleted = (hdr_flags & TDB_KV_FLAG_TOMBSTONE) != 0;
                    int is_expired = (hdr_ttl > 0 && time(NULL) > hdr_ttl);

                    if (is_deleted || is_expired)
                    {
                        if (data != block->data) free(data);
                        block_manager_block_free(block);
                        block_manager_cursor_free(cursor);
                        return TDB_ERR_NOT_FOUND;
                    }

                    /* copy value */
                    if (hdr_value_size > 0)
                    {
                        *value = malloc(hdr_value_size);
                        if (!*value)
                        {
                            if (data != block->data) free(data);
                            block_manager_block_free(block);
                            block_manager_cursor_free(cursor);
                            return -1;
                        }
                        memcpy(*value, block_value, hdr_value_size);
                    }
                    else
                    {
                        *value = malloc(1);
                        if (!*value)
                        {
                            if (data != block->data) free(data);
                            block_manager_block_free(block);
                            block_manager_cursor_free(cursor);
                            return -1;
                        }
                    }
                    *value_size = hdr_value_size;

                    if (data != block->data) free(data);
                    block_manager_block_free(block);
                    block_manager_cursor_free(cursor);
                    return 0;
                }

                if (data != block->data) free(data);
                block_manager_block_free(block);
            }
            block_manager_cursor_next(cursor);
        }

        block_manager_cursor_free(cursor);
        return -1; /* not found */
    }

    /* read block at byte offset from block index */
    block_manager_cursor_t *cursor = NULL;
    if (block_manager_cursor_init(&cursor, sstable->block_manager) != 0) return -1;

    /* use direct byte offset positioning for O(1) access */
    if (block_manager_cursor_goto(cursor, (uint64_t)block_offset) != 0)
    {
        block_manager_cursor_free(cursor);
        return -1;
    }

    block_manager_block_t *block = block_manager_cursor_read(cursor);
    block_manager_cursor_free(cursor);

    if (!block || !block->data)
    {
        if (block) block_manager_block_free(block);
        return TDB_ERR_CORRUPT; /* checksum verification failed or block corrupted */
    }

    /* decompress if needed */
    uint8_t *data = block->data;
    size_t data_size = block->size;

    if (sstable->cf->config.enable_compression)
    {
        size_t decompressed_size = 0;
        uint8_t *decompressed = decompress_data(data, data_size, &decompressed_size,
                                                sstable->cf->config.compression_algorithm);
        if (decompressed)
        {
            data = decompressed;
            data_size = decompressed_size;
        }
    }

    /* parse block using [header][key][value] */
    if (data_size < sizeof(tidesdb_kv_pair_header_t))
    {
        if (data != block->data) free(data);
        block_manager_block_free(block);
        return -1;
    }

    uint8_t hdr_version, hdr_flags;
    uint32_t hdr_key_size, hdr_value_size;
    int64_t hdr_ttl;
    deserialize_kv_header(data, &hdr_version, &hdr_flags, &hdr_key_size, &hdr_value_size, &hdr_ttl);

    uint8_t *ptr = data + TDB_KV_HEADER_SIZE;
    uint8_t *block_key = ptr;
    ptr += hdr_key_size;
    uint8_t *block_value = ptr;

    /* verify key matches */
    if (key_size != hdr_key_size || memcmp(key, block_key, key_size) != 0)
    {
        if (data != block->data) free(data);
        block_manager_block_free(block);
        return -1;
    }

    /* check if deleted (tombstone) or expired */
    int is_deleted = (hdr_flags & TDB_KV_FLAG_TOMBSTONE) != 0;
    int is_expired = (hdr_ttl > 0 && time(NULL) > hdr_ttl);

    if (is_deleted || is_expired)
    {
        if (data != block->data) free(data);
        block_manager_block_free(block);
        return TDB_ERR_NOT_FOUND;
    }

    /* copy value, handle empty values */
    if (hdr_value_size > 0)
    {
        *value = malloc(hdr_value_size);
        if (!*value)
        {
            if (data != block->data) free(data);
            block_manager_block_free(block);
            return -1;
        }
        memcpy(*value, block_value, hdr_value_size);
    }
    else
    {
        *value = malloc(1);
        if (!*value)
        {
            if (data != block->data) free(data);
            block_manager_block_free(block);
            return -1;
        }
    }
    *value_size = hdr_value_size;

    if (data != block->data) free(data);
    block_manager_block_free(block);
    return 0;
}

/*
 * tidesdb_sstable_free
 * frees an sstable
 * @param sstable sstable to free
 */
static void tidesdb_sstable_free(tidesdb_sstable_t *sstable)
{
    if (!sstable) return;

    /* evict block_manager from cache so we can properly close it */
    if (sstable->block_manager && sstable->cf && sstable->cf->db &&
        sstable->cf->db->block_manager_cache)
    {
        char sstable_path[TDB_MAX_PATH_LENGTH];
        get_sstable_path(sstable->cf, sstable->id, sstable_path);
        lru_cache_remove(sstable->cf->db->block_manager_cache, sstable_path);
    }

    if (sstable->index)
    {
        succinct_trie_free(sstable->index);
    }

    if (sstable->bloom_filter)
    {
        bloom_filter_free(sstable->bloom_filter);
    }

    if (sstable->min_key) free(sstable->min_key);
    if (sstable->max_key) free(sstable->max_key);

    pthread_mutex_destroy(&sstable->ref_lock);
    free(sstable);
}

/*
 * tidesdb_txn_get_internal
 * internal implementation of get operation
 * @param txn transaction
 * @param cf column family
 * @param key key to get
 * @param key_size size of key
 * @param value pointer to store value
 * @param value_size pointer to store value size
 * @return 0 on success, -1 on failure
 */
static int tidesdb_txn_get_internal(tidesdb_txn_t *txn, tidesdb_column_family_t *cf,
                                    const uint8_t *key, size_t key_size, uint8_t **value,
                                    size_t *value_size)
{
    if (!txn || !cf || !key || !value || !value_size) return -1;

    tidesdb_memtable_t *active_mt = atomic_load(&cf->active_memtable);
    if (active_mt && active_mt->memtable)
    {
        tidesdb_memtable_acquire(active_mt);

        uint8_t *mem_value = NULL;
        size_t mem_value_size = 0;
        uint8_t deleted = 0;

        int memtable_result = skip_list_get(active_mt->memtable, key, key_size, &mem_value,
                                            &mem_value_size, &deleted);

        if (memtable_result == 0)
        {
            /* key found in active memtable */
            if (deleted)
            {
                /* key is tombstoned */
                if (mem_value) free(mem_value);
                tidesdb_memtable_release(active_mt);
                return -1;
            }

            /* handle both non-empty and empty values */
            if (mem_value_size > 0)
            {
                *value = malloc(mem_value_size);
                if (!*value)
                {
                    if (mem_value) free(mem_value);
                    tidesdb_memtable_release(active_mt);
                    return -1;
                }
                memcpy(*value, mem_value, mem_value_size);
            }
            else
            {
                /* empty value, allocate minimal buffer */
                *value = malloc(1);
                if (!*value)
                {
                    if (mem_value) free(mem_value);
                    tidesdb_memtable_release(active_mt);
                    return -1;
                }
            }

            *value_size = mem_value_size;
            if (mem_value) free(mem_value);
            tidesdb_memtable_release(active_mt);
            return 0;
        }

        tidesdb_memtable_release(active_mt);
    }

    /* check immutable memtables; snapshot them WITHOUT flush_lock to avoid serializing reads
     * we use cf_lock (read lock) which allows concurrent readers */
    tidesdb_memtable_t **immutable_snapshot = NULL;
    size_t num_immutable = 0;

    if (cf->immutable_memtables)
    {
        /* get count first without lock */
        pthread_rwlock_rdlock(&cf->cf_lock);
        num_immutable = queue_size(cf->immutable_memtables);
        pthread_rwlock_unlock(&cf->cf_lock);

        if (num_immutable > 0)
        {
            /* allocate OUTSIDE lock to avoid heap contention under lock */
            immutable_snapshot = malloc(num_immutable * sizeof(tidesdb_memtable_t *));
            if (immutable_snapshot)
            {
                /* now acquire lock and snapshot quickly */
                pthread_rwlock_rdlock(&cf->cf_lock);
                size_t actual_count = queue_size(cf->immutable_memtables);
                /* use smaller of the two to avoid overrun */
                if (actual_count > num_immutable) actual_count = num_immutable;

                for (size_t i = 0; i < actual_count; i++)
                {
                    tidesdb_memtable_t *imt =
                        (tidesdb_memtable_t *)queue_peek_at(cf->immutable_memtables, i);
                    if (imt)
                    {
                        tidesdb_memtable_acquire(imt);
                        immutable_snapshot[i] = imt;
                    }
                    else
                    {
                        immutable_snapshot[i] = NULL;
                    }
                }
                num_immutable = actual_count;
                pthread_rwlock_unlock(&cf->cf_lock);
            }
        }

        /* now search through snapshot from newest to oldest (reverse order) */
        if (immutable_snapshot)
        {
            for (ssize_t i = (ssize_t)num_immutable - 1; i >= 0; i--)
            {
                tidesdb_memtable_t *imt = immutable_snapshot[i];
                if (imt && imt->memtable)
                {
                    uint8_t *mem_value = NULL;
                    size_t mem_value_size = 0;
                    uint8_t deleted = 0;

                    int result = skip_list_get(imt->memtable, key, key_size, &mem_value,
                                               &mem_value_size, &deleted);

                    if (result == 0)
                    {
                        /* release all immutable memtable references */
                        for (size_t j = 0; j < num_immutable; j++)
                        {
                            if (immutable_snapshot[j])
                                tidesdb_memtable_release(immutable_snapshot[j]);
                        }
                        free(immutable_snapshot);

                        if (deleted)
                        {
                            if (mem_value) free(mem_value);
                            return -1;
                        }

                        if (mem_value_size > 0)
                        {
                            *value = malloc(mem_value_size);
                            if (!*value)
                            {
                                if (mem_value) free(mem_value);
                                return -1;
                            }
                            memcpy(*value, mem_value, mem_value_size);
                        }
                        else
                        {
                            *value = malloc(1);
                            if (!*value)
                            {
                                if (mem_value) free(mem_value);
                                return -1;
                            }
                        }

                        *value_size = mem_value_size;
                        if (mem_value) free(mem_value);
                        return 0;
                    }
                }
            }

            /* release all immutable memtable references */
            for (size_t i = 0; i < num_immutable; i++)
            {
                if (immutable_snapshot[i]) tidesdb_memtable_release(immutable_snapshot[i]);
            }
            free(immutable_snapshot);
        }
    }

    /* snapshot sstables -- allocate outside lock to avoid heap contention */
    int num_ssts = atomic_load(&cf->num_sstables);

    tidesdb_sstable_t **sst_snapshot = NULL;
    if (num_ssts > 0)
    {
        /* allocate OUTSIDE lock */
        sst_snapshot = malloc((size_t)num_ssts * sizeof(tidesdb_sstable_t *));
        if (sst_snapshot)
        {
            /* acquire lock only for copying pointers and incrementing refs */
            pthread_rwlock_rdlock(&cf->cf_lock);
            int actual_count = atomic_load(&cf->num_sstables);
            /* use smaller count to avoid overrun */
            if (actual_count > num_ssts) actual_count = num_ssts;

            for (int i = 0; i < actual_count; i++)
            {
                sst_snapshot[i] = cf->sstables[i];
                if (sst_snapshot[i])
                {
                    tidesdb_sstable_acquire(sst_snapshot[i]);
                }
            }
            num_ssts = actual_count;
            pthread_rwlock_unlock(&cf->cf_lock);
        }
    }

    /* now search sstables without holding any locks */
    if (sst_snapshot)
    {
        for (int i = num_ssts - 1; i >= 0; i--)
        {
            tidesdb_sstable_t *sst = sst_snapshot[i];
            if (!sst) continue;

            /* reference already acquired while holding lock */
            /* quick bloom filter check */
            if (sst->bloom_filter)
            {
                if (!bloom_filter_contains(sst->bloom_filter, key, key_size))
                {
                    /* definitely not in this sstable, release and continue */
                    tidesdb_sstable_release(sst);
                    sst_snapshot[i] = NULL; /* mark as released */
                    continue;
                }
            }

            uint8_t *sst_value = NULL;
            size_t sst_value_size = 0;

            int result = tidesdb_sstable_get(sst, key, key_size, &sst_value, &sst_value_size);
            tidesdb_sstable_release(sst);
            sst_snapshot[i] = NULL; /* mark as released */

            if (result == 0)
            {
                /* release remaining sstable references */
                for (int j = i - 1; j >= 0; j--)
                {
                    if (sst_snapshot[j])
                    {
                        tidesdb_sstable_release(sst_snapshot[j]);
                        sst_snapshot[j] = NULL;
                    }
                }
                free(sst_snapshot);
                *value = sst_value;
                *value_size = sst_value_size;
                return 0;
            }
            else if (result == TDB_ERR_CORRUPT)
            {
                /* release remaining sstable references */
                for (int j = i - 1; j >= 0; j--)
                {
                    if (sst_snapshot[j])
                    {
                        tidesdb_sstable_release(sst_snapshot[j]);
                        sst_snapshot[j] = NULL;
                    }
                }
                free(sst_snapshot);
                return TDB_ERR_CORRUPT;
            }
            else if (result == TDB_ERR_NOT_FOUND)
            {
                /* Key not in this sstable, continue to next one */
                continue;
            }
            /* else continue to next sstable */
        }

        /* release all remaining references */
        for (int i = 0; i < num_ssts; i++)
        {
            if (sst_snapshot[i]) tidesdb_sstable_release(sst_snapshot[i]);
        }
        free(sst_snapshot);
    }
    return -1;
}

int tidesdb_txn_begin(tidesdb_t *db, tidesdb_column_family_t *cf, tidesdb_txn_t **txn)
{
    if (!db || !cf || !txn) return TDB_ERR_INVALID_ARGS;

    *txn = malloc(sizeof(tidesdb_txn_t));
    if (!*txn) return TDB_ERR_MEMORY;

    (*txn)->db = db;
    (*txn)->cf = cf;
    (*txn)->operations = NULL;
    (*txn)->num_ops = 0;
    (*txn)->op_capacity = 0;
    (*txn)->committed = 0;
    (*txn)->read_only = 0;

    return 0;
}

int tidesdb_txn_begin_read(tidesdb_t *db, tidesdb_column_family_t *cf, tidesdb_txn_t **txn)
{
    if (!db || !cf || !txn) return TDB_ERR_INVALID_ARGS;

    *txn = malloc(sizeof(tidesdb_txn_t));
    if (!*txn) return TDB_ERR_MEMORY;

    (*txn)->db = db;
    (*txn)->cf = cf;
    (*txn)->operations = NULL;
    (*txn)->num_ops = 0;
    (*txn)->op_capacity = 0;
    (*txn)->committed = 0;
    (*txn)->read_only = 1;

    return 0;
}

int tidesdb_txn_get(tidesdb_txn_t *txn, const uint8_t *key, size_t key_size, uint8_t **value,
                    size_t *value_size)
{
    if (!txn || !key || !value || !value_size) return TDB_ERR_INVALID_ARGS;
    if (key_size == 0) return TDB_ERR_INVALID_ARGS; /* keys must have non-zero length */

    tidesdb_column_family_t *cf = txn->cf;
    if (!cf) return TDB_ERR_INVALID_ARGS;

    /* check pending writes in transaction first (read your own writes) */
    if (!txn->read_only)
    {
        for (int i = txn->num_ops - 1; i >= 0; i--)
        {
            tidesdb_operation_t *op = &txn->operations[i];
            if (strcmp(op->cf_name, cf->name) == 0 && op->key_size == key_size &&
                memcmp(op->key, key, key_size) == 0)
            {
                if (op->type == TIDESDB_OP_DELETE)
                {
                    return TDB_ERR_NOT_FOUND;
                }
                if (op->type == TIDESDB_OP_PUT)
                {
                    *value = malloc(op->value_size);
                    if (*value)
                    {
                        memcpy(*value, op->value, op->value_size);
                        *value_size = op->value_size;
                        return 0;
                    }
                    return TDB_ERR_MEMORY;
                }
            }
        }
    }

    return tidesdb_txn_get_internal(txn, cf, key, key_size, value, value_size);
}

int tidesdb_txn_put(tidesdb_txn_t *txn, const uint8_t *key, size_t key_size, const uint8_t *value,
                    size_t value_size, time_t ttl)
{
    if (!txn || !key || !value) return TDB_ERR_INVALID_ARGS;
    if (key_size == 0) return TDB_ERR_INVALID_ARGS;
    if (txn->committed == 1) return TDB_ERR_TXN_COMMITTED;
    if (txn->committed == -1) return TDB_ERR_TXN_ABORTED;
    if (txn->read_only) return TDB_ERR_READONLY;

    tidesdb_column_family_t *cf = txn->cf;
    if (!cf) return TDB_ERR_INVALID_ARGS;

    /* validate key/value sizes against memory limits */
    int validation_result = tidesdb_validate_kv_size(txn->db, key_size, value_size);
    if (validation_result != 0)
    {
        return validation_result;
    }

    if (txn->num_ops >= txn->op_capacity)
    {
        int new_cap = txn->op_capacity == 0 ? 8 : txn->op_capacity * 2;
        tidesdb_operation_t *new_ops =
            realloc(txn->operations, (size_t)new_cap * sizeof(tidesdb_operation_t));
        if (!new_ops) return TDB_ERR_MEMORY;
        txn->operations = new_ops;
        txn->op_capacity = new_cap;
    }

    tidesdb_operation_t *op = &txn->operations[txn->num_ops];
    op->type = TIDESDB_OP_PUT;
    size_t put_cf_len = strlen(cf->name);
    if (put_cf_len >= TDB_MAX_CF_NAME_LENGTH) put_cf_len = TDB_MAX_CF_NAME_LENGTH - 1;
    memcpy(op->cf_name, cf->name, put_cf_len);
    op->cf_name[put_cf_len] = '\0';

    op->key = malloc(key_size);
    if (!op->key) return TDB_ERR_MEMORY;
    memcpy(op->key, key, key_size);
    op->key_size = key_size;

    op->value = malloc(value_size);
    if (!op->value)
    {
        free(op->key);
        return TDB_ERR_MEMORY;
    }
    memcpy(op->value, value, value_size);
    op->value_size = value_size;
    op->ttl = ttl;

    txn->num_ops++;
    return 0;
}

int tidesdb_txn_delete(tidesdb_txn_t *txn, const uint8_t *key, size_t key_size)
{
    if (!txn || !key) return TDB_ERR_INVALID_ARGS;
    if (key_size == 0) return TDB_ERR_INVALID_ARGS; /* keys must have non-zero length */
    if (txn->committed == 1) return TDB_ERR_TXN_COMMITTED;
    if (txn->committed != 0) return TDB_ERR_TXN_ABORTED;
    if (txn->read_only) return TDB_ERR_READONLY;

    tidesdb_column_family_t *cf = txn->cf;
    if (!cf) return TDB_ERR_INVALID_ARGS;

    if (txn->num_ops >= txn->op_capacity)
    {
        int new_cap = txn->op_capacity == 0 ? 8 : txn->op_capacity * 2;
        tidesdb_operation_t *new_ops =
            realloc(txn->operations, (size_t)new_cap * sizeof(tidesdb_operation_t));
        if (!new_ops) return TDB_ERR_MEMORY;
        txn->operations = new_ops;
        txn->op_capacity = new_cap;
    }

    tidesdb_operation_t *op = &txn->operations[txn->num_ops];
    op->type = TIDESDB_OP_DELETE;
    size_t del_cf_len = strlen(cf->name);
    if (del_cf_len >= TDB_MAX_CF_NAME_LENGTH) del_cf_len = TDB_MAX_CF_NAME_LENGTH - 1;
    memcpy(op->cf_name, cf->name, del_cf_len);
    op->cf_name[del_cf_len] = '\0';

    /* allocate and copy key */
    op->key = malloc(key_size);
    if (!op->key) return TDB_ERR_MEMORY;
    memcpy(op->key, key, key_size);
    op->key_size = key_size;
    op->value = NULL;
    op->value_size = 0;
    op->ttl = 0;

    txn->num_ops++;
    return 0;
}

int tidesdb_txn_commit(tidesdb_txn_t *txn)
{
    if (!txn) return TDB_ERR_INVALID_ARGS;
    if (txn->committed == 1) return TDB_ERR_TXN_COMMITTED;
    if (txn->committed == -1) return TDB_ERR_TXN_ABORTED;
    if (txn->read_only)
    {
        txn->committed = 1;
        return 0; /* nothing to commit for read-only */
    }

    if (txn->num_ops == 1)
    {
        tidesdb_operation_t *op = &txn->operations[0];
        tidesdb_column_family_t *cf = tidesdb_get_column_family(txn->db, op->cf_name);
        if (!cf) return TDB_ERR_NOT_FOUND;

        tidesdb_memtable_t *mt = atomic_load(&cf->active_memtable);
        if (!mt) return -1;

        tidesdb_memtable_acquire(mt);

        /* write to WAL -- prepare block outside lock, then just write */
        if (mt->wal)
        {
            size_t entry_size = TDB_KV_HEADER_SIZE + op->key_size;
            if (op->type == TIDESDB_OP_PUT) entry_size += op->value_size;

            /* alloc and serialize OUTSIDE the lock */
            uint8_t *wal_entry = malloc(entry_size);
            if (wal_entry)
            {
                uint8_t version = TDB_KV_FORMAT_VERSION;
                uint8_t flags = (op->type == TIDESDB_OP_DELETE) ? TDB_KV_FLAG_TOMBSTONE : 0;
                uint32_t key_size = (uint32_t)op->key_size;
                uint32_t value_size = (op->type == TIDESDB_OP_PUT) ? (uint32_t)op->value_size : 0;
                int64_t ttl = (op->type == TIDESDB_OP_PUT) ? (int64_t)op->ttl : 0;

                serialize_kv_header(wal_entry, version, flags, key_size, value_size, ttl);
                memcpy(wal_entry + TDB_KV_HEADER_SIZE, op->key, op->key_size);
                if (op->type == TIDESDB_OP_PUT)
                {
                    memcpy(wal_entry + TDB_KV_HEADER_SIZE + op->key_size, op->value,
                           op->value_size);
                }

                /* create block structure */
                block_manager_block_t *block =
                    block_manager_block_create_from_buffer(entry_size, wal_entry);
                if (block)
                {
                    block_manager_block_write(mt->wal, block);
                    block_manager_block_free(block);
                }
                else
                {
                    free(wal_entry);
                }
            }
        }

        /* serialize writes with memtable_write_lock (doesn't block readers) */
        pthread_mutex_lock(&cf->memtable_write_lock);

        int result = 0;
        if (op->type == TIDESDB_OP_PUT)
        {
            result = skip_list_put(mt->memtable, op->key, op->key_size, op->value, op->value_size,
                                   op->ttl);
        }
        else if (op->type == TIDESDB_OP_DELETE)
        {
            uint8_t empty_value = 0;
            skip_list_put(mt->memtable, op->key, op->key_size, &empty_value, 0, 0);

            skip_list_delete(mt->memtable, op->key, op->key_size);
        }

        pthread_mutex_unlock(&cf->memtable_write_lock);

        tidesdb_memtable_release(mt);

        if (result != 0) return -1;

        /* check if flush needed */
        tidesdb_check_and_flush(cf);

        txn->committed = 1;
        return 0;
    }

    /* calculate total WAL size for all operations */
    size_t total_wal_size = 0;
    tidesdb_memtable_t *active_mt = NULL;
    tidesdb_column_family_t *first_cf = NULL;

    for (int i = 0; i < txn->num_ops; i++)
    {
        tidesdb_operation_t *op = &txn->operations[i];
        size_t entry_size = TDB_KV_HEADER_SIZE + op->key_size;
        if (op->type == TIDESDB_OP_PUT)
        {
            entry_size += op->value_size;
        }
        total_wal_size += entry_size;
    }

    /* get CF for WAL write */
    if (txn->num_ops > 0)
    {
        first_cf = tidesdb_get_column_family(txn->db, txn->operations[0].cf_name);
    }

    /* allocate single buffer for all WAL entries */
    uint8_t *batch_wal = NULL;
    if (total_wal_size > 0 && txn->num_ops > 0 && first_cf)
    {
        active_mt = atomic_load(&first_cf->active_memtable);
        if (active_mt && active_mt->wal)
        {
            batch_wal = malloc(total_wal_size);
            if (batch_wal)
            {
                uint8_t *ptr = batch_wal;

                /* pack all WAL entries into single buffer using cross-platform serialization */
                for (int i = 0; i < txn->num_ops; i++)
                {
                    tidesdb_operation_t *op = &txn->operations[i];

                    uint8_t version = TDB_KV_FORMAT_VERSION;
                    uint8_t flags = (op->type == TIDESDB_OP_DELETE) ? TDB_KV_FLAG_TOMBSTONE : 0;
                    uint32_t key_size = (uint32_t)op->key_size;
                    uint32_t value_size =
                        (op->type == TIDESDB_OP_PUT) ? (uint32_t)op->value_size : 0;
                    int64_t ttl = (op->type == TIDESDB_OP_PUT) ? (int64_t)op->ttl : 0;

                    serialize_kv_header(ptr, version, flags, key_size, value_size, ttl);
                    ptr += TDB_KV_HEADER_SIZE;
                    memcpy(ptr, op->key, op->key_size);
                    ptr += op->key_size;

                    if (op->type == TIDESDB_OP_PUT)
                    {
                        memcpy(ptr, op->value, op->value_size);
                        ptr += op->value_size;
                    }
                }

                /* single WAL write for entire transaction */
                tidesdb_memtable_acquire(active_mt);
                block_manager_block_t *block =
                    block_manager_block_create_from_buffer(total_wal_size, batch_wal);
                if (block)
                {
                    block_manager_block_write(active_mt->wal, block);
                    block_manager_block_free(block); /* this frees batch_wal too */
                }
                else
                {
                    free(batch_wal); /* free if block creation failed */
                }
                tidesdb_memtable_release(active_mt);
            }
        }
    }

    /* now update memtable for all operations */
    /*  acquire memtable reference once for entire batch */
    tidesdb_column_family_t *last_cf = NULL;
    tidesdb_memtable_t *batch_mt = NULL;

    if (txn->num_ops > 0)
    {
        tidesdb_column_family_t *cf =
            tidesdb_get_column_family(txn->db, txn->operations[0].cf_name);
        if (!cf) return TDB_ERR_NOT_FOUND;

        batch_mt = atomic_load(&cf->active_memtable);
        if (!batch_mt) return -1;

        /* acquire once for entire batch */
        tidesdb_memtable_acquire(batch_mt);
        last_cf = cf;
    }

    /* serialize writes with memtable_write_lock (doesn't block readers) */
    if (last_cf)
    {
        pthread_mutex_lock(&last_cf->memtable_write_lock);
    }

    for (int i = 0; i < txn->num_ops; i++)
    {
        tidesdb_operation_t *op = &txn->operations[i];

        if (op->type == TIDESDB_OP_PUT)
        {
            /* WAL write already done in batch above */
            int result = skip_list_put(batch_mt->memtable, op->key, op->key_size, op->value,
                                       op->value_size, op->ttl);

            if (result != 0)
            {
                pthread_mutex_unlock(&last_cf->memtable_write_lock);
                tidesdb_memtable_release(batch_mt);
                return -1;
            }
        }
        else if (op->type == TIDESDB_OP_DELETE)
        {
            /* WAL write already done in batch above */
            uint8_t empty_value = 0;
            skip_list_put(batch_mt->memtable, op->key, op->key_size, &empty_value, 0, 0);
            skip_list_delete(batch_mt->memtable, op->key, op->key_size);
            /* if delete fails, the put succeeded so we have a valid entry, continue */
        }

        /* check if memtable needs flushing after this operation */
        if (last_cf && batch_mt)
        {
            size_t memtable_size = atomic_load(&batch_mt->memtable->total_size);
            size_t wal_size = batch_mt->wal ? (size_t)batch_mt->wal->current_file_size : 0;

            if (memtable_size >= last_cf->config.memtable_flush_size ||
                wal_size >= last_cf->config.memtable_flush_size)
            {
                /* need to flush -- release lock, memtable, and trigger */
                pthread_mutex_unlock(&last_cf->memtable_write_lock);
                tidesdb_memtable_release(batch_mt);

                tidesdb_check_and_flush(last_cf);

                /* get new active memtable and re-acquire lock */
                batch_mt = atomic_load(&last_cf->active_memtable);
                if (!batch_mt)
                {
                    return -1;
                }
                tidesdb_memtable_acquire(batch_mt);
                pthread_mutex_lock(&last_cf->memtable_write_lock);
            }
        }
    }

    if (last_cf)
    {
        pthread_mutex_unlock(&last_cf->memtable_write_lock);
    }

    /* release once after entire batch */
    if (batch_mt)
    {
        tidesdb_memtable_release(batch_mt);
    }

    /* check if we need to flush ONCE after all operations */
    if (last_cf)
    {
        tidesdb_check_and_flush(last_cf);
    }

    txn->committed = 1;
    return 0;
}

int tidesdb_txn_rollback(tidesdb_txn_t *txn)
{
    if (!txn) return TDB_ERR_INVALID_ARGS;
    if (txn->committed == 1) return TDB_ERR_TXN_COMMITTED;
    if (txn->committed == -1) return TDB_ERR_TXN_ABORTED;

    /* mark as rolled back, operations won't be committed */
    txn->committed = -1;
    return 0;
}

void tidesdb_txn_free(tidesdb_txn_t *txn)
{
    if (!txn) return;

    for (int i = 0; i < txn->num_ops; i++)
    {
        tidesdb_operation_t *op = &txn->operations[i];
        if (op->key) free(op->key);
        if (op->value) free(op->value);
    }

    if (txn->operations) free(txn->operations);
    free(txn);
}

/*
 * parse_block
 * parses a block from the block manager
 * @param block block to parse
 * @param cf column family
 * @param key pointer to store parsed key
 * @param key_size pointer to store parsed key size
 * @param value pointer to store parsed value
 * @param value_size pointer to store parsed value size
 * @param deleted pointer to store deleted flag
 * @param ttl pointer to store TTL
 * @return 0 on success, -1 on failure
 */
static int parse_block(block_manager_block_t *block, tidesdb_column_family_t *cf, uint8_t **key,
                       size_t *key_size, uint8_t **value, size_t *value_size, uint8_t *deleted,
                       time_t *ttl)
{
    if (!block || !block->data) return -1;

    uint8_t *data = block->data;
    size_t data_size = block->size;

    /* detect metadata blocks (bloom filter, index, or meta) */
    if (data_size >= sizeof(uint32_t))
    {
        uint32_t potential_magic = decode_uint32_le(data);
        if (potential_magic == TDB_SST_META_MAGIC)
        {
            /* this is a metadata block, not a KV block */
            return -1;
        }
    }

    if (cf->config.enable_compression)
    {
        size_t decompressed_size = 0;
        uint8_t *decompressed =
            decompress_data(data, data_size, &decompressed_size, cf->config.compression_algorithm);
        if (!decompressed)
        {
            return -1;
        }
        data = decompressed;
        data_size = decompressed_size;
    }

    /* parse format [header][key][value] */
    if (data_size < TDB_KV_HEADER_SIZE)
    {
        if (data != block->data) free(data);
        return -1;
    }

    /* validate this looks like a KV block by checking header */
    uint8_t check_version = data[0];
    if (check_version != TDB_KV_FORMAT_VERSION)
    {
        /* not a valid KV block - likely a bloom filter or index block */
        if (data != block->data) free(data);
        return -1;
    }

    if (data_size < TDB_KV_HEADER_SIZE)
    {
        if (data != block->data) free(data);
        return -1;
    }

    uint8_t hdr_version, hdr_flags;
    uint32_t hdr_key_size, hdr_value_size;
    int64_t hdr_ttl;
    uint8_t *ptr = data;
    deserialize_kv_header(ptr, &hdr_version, &hdr_flags, &hdr_key_size, &hdr_value_size, &hdr_ttl);
    ptr += TDB_KV_HEADER_SIZE;

    if (hdr_version != TDB_KV_FORMAT_VERSION)
    {
        if (data != block->data) free(data);
        return TDB_ERR_CORRUPT; /* invalid format version indicates corruption */
    }

    /* verify we have enough data for key and value */
    if (data_size < TDB_KV_HEADER_SIZE + hdr_key_size + hdr_value_size)
    {
        if (data != block->data) free(data);
        return TDB_ERR_CORRUPT; /* truncated data indicates corruption */
    }

    *key = malloc(hdr_key_size);
    if (!*key)
    {
        if (data != block->data) free(data);
        return -1;
    }
    memcpy(*key, ptr, hdr_key_size);
    *key_size = hdr_key_size;
    ptr += hdr_key_size;

    if (hdr_value_size > 0)
    {
        *value = malloc(hdr_value_size);
        if (!*value)
        {
            free(*key);
            if (data != block->data) free(data);
            return -1;
        }
        memcpy(*value, ptr, hdr_value_size);
    }
    else
    {
        *value = malloc(1);
        if (!*value)
        {
            free(*key);
            if (data != block->data) free(data);
            return -1;
        }
    }

    *value_size = hdr_value_size;
    *ttl = (time_t)hdr_ttl;
    *deleted = (hdr_flags & TDB_KV_FLAG_TOMBSTONE) ? 1 : 0;

    if (data != block->data) free(data);
    return 0;
}

/*
 * compare_keys_with_cf
 * compares two keys using the column family's comparator
 * @param cf column family
 * @param key1 first key
 * @param key1_size size of first key
 * @param key2 second key
 * @param key2_size size of second key
 * @return negative if key1 < key2, zero if equal, positive if key1 > key2
 */
static int compare_keys_with_cf(tidesdb_column_family_t *cf, const uint8_t *key1, size_t key1_size,
                                const uint8_t *key2, size_t key2_size)
{
    /* use the column family's memtable comparator (which is set from config) */
    tidesdb_memtable_t *active_mt = atomic_load(&cf->active_memtable);
    if (active_mt && active_mt->memtable)
    {
        tidesdb_memtable_acquire(active_mt);
        int result = skip_list_compare_keys(active_mt->memtable, key1, key1_size, key2, key2_size);
        tidesdb_memtable_release(active_mt);
        return result;
    }
    /* fallback to memcmp if no active memtable */
    size_t min_size = key1_size < key2_size ? key1_size : key2_size;
    int cmp = memcmp(key1, key2, min_size);
    if (cmp != 0) return cmp;
    if (key1_size < key2_size) return -1;
    if (key1_size > key2_size) return 1;
    return 0;
}

int tidesdb_iter_new(tidesdb_txn_t *txn, tidesdb_iter_t **iter)
{
    if (!txn || !iter) return TDB_ERR_INVALID_ARGS;

    tidesdb_column_family_t *cf = txn->cf;
    if (!cf) return TDB_ERR_INVALID_ARGS;

    if (atomic_load(&cf->is_dropping)) return TDB_ERR_INVALID_CF;

    *iter = malloc(sizeof(tidesdb_iter_t));
    if (!*iter) return TDB_ERR_MEMORY;

    (*iter)->txn = txn;
    (*iter)->cf = cf;
    (*iter)->memtable_cursor = NULL;
    (*iter)->active_memtable = NULL;
    (*iter)->immutable_memtable_cursors = NULL;
    (*iter)->immutable_memtables = NULL;
    (*iter)->num_immutable_cursors = 0;
    (*iter)->sstable_cursors = NULL;
    (*iter)->sstables = NULL;
    (*iter)->num_sstable_cursors = 0;
    (*iter)->sstable_blocks_read = NULL;
    (*iter)->current_key = NULL;
    (*iter)->current_value = NULL;
    (*iter)->current_key_size = 0;
    (*iter)->current_value_size = 0;
    (*iter)->current_deleted = 0;
    (*iter)->valid = 0;
    (*iter)->direction = 1; /* forward by default */
    (*iter)->heap = NULL;
    (*iter)->heap_size = 0;
    (*iter)->heap_capacity = 0;

    tidesdb_memtable_t *active_mt = atomic_load(&cf->active_memtable);
    if (active_mt && active_mt->memtable)
    {
        tidesdb_memtable_acquire(active_mt);
        (*iter)->active_memtable = active_mt; /* store the reference */
        (*iter)->memtable_cursor = skip_list_cursor_init(active_mt->memtable);
        if (!(*iter)->memtable_cursor)
        {
            /* failed to create cursor -- release memtable and continue without it */
            tidesdb_memtable_release(active_mt);
            (*iter)->active_memtable = NULL;
        }
    }
    if (cf->immutable_memtables)
    {
        /* acquire flush_lock first to prevent races with flush operations */
        pthread_mutex_lock(&cf->flush_lock);

        /* then acquire cf_lock and hold it for the entire snapshot operation */
        pthread_rwlock_rdlock(&cf->cf_lock);
        size_t num_immutable = queue_size(cf->immutable_memtables);

        if (num_immutable > 0)
        {
            (*iter)->immutable_memtable_cursors =
                malloc(num_immutable * sizeof(skip_list_cursor_t *));
            (*iter)->immutable_memtables = malloc(num_immutable * sizeof(tidesdb_memtable_t *));
            if (!(*iter)->immutable_memtable_cursors || !(*iter)->immutable_memtables)
            {
                pthread_rwlock_unlock(&cf->cf_lock);
                pthread_mutex_unlock(&cf->flush_lock);
                if ((*iter)->immutable_memtable_cursors) free((*iter)->immutable_memtable_cursors);
                if ((*iter)->immutable_memtables) free((*iter)->immutable_memtables);
                if ((*iter)->memtable_cursor) skip_list_cursor_free((*iter)->memtable_cursor);
                if ((*iter)->active_memtable) tidesdb_memtable_release((*iter)->active_memtable);
                free(*iter);
                return TDB_ERR_MEMORY;
            }

            (*iter)->num_immutable_cursors = (int)num_immutable;

            /* snapshot all memtables atomically while holding lock */
            for (size_t i = 0; i < num_immutable; i++)
            {
                tidesdb_memtable_t *imt =
                    (tidesdb_memtable_t *)queue_peek_at(cf->immutable_memtables, i);
                if (imt)
                {
                    tidesdb_memtable_acquire(imt);
                    (*iter)->immutable_memtables[i] = imt;
                }
                else
                {
                    (*iter)->immutable_memtables[i] = NULL;
                }
            }

            /* now we can release the locks -- we have references to all memtables */
            pthread_rwlock_unlock(&cf->cf_lock);
            pthread_mutex_unlock(&cf->flush_lock);

            /* create cursors without holding any locks */
            for (size_t i = 0; i < num_immutable; i++)
            {
                if ((*iter)->immutable_memtables[i] && (*iter)->immutable_memtables[i]->memtable)
                {
                    (*iter)->immutable_memtable_cursors[i] =
                        skip_list_cursor_init((*iter)->immutable_memtables[i]->memtable);
                }
                else
                {
                    (*iter)->immutable_memtable_cursors[i] = NULL;
                }
            }
        }
        else
        {
            pthread_rwlock_unlock(&cf->cf_lock);
            pthread_mutex_unlock(&cf->flush_lock);
        }
    }

    /* acquire lock and snapshot sstables atomically */
    pthread_rwlock_rdlock(&cf->cf_lock);
    int num_ssts = atomic_load(&cf->num_sstables);
    /* ensure we see all sstable pointers written before count was incremented */
    atomic_thread_fence(memory_order_acquire);
    (*iter)->num_sstable_cursors = num_ssts;
    (*iter)->sstable_cursors = NULL;
    (*iter)->sstables = NULL;
    (*iter)->sstable_blocks_read = NULL;

    if (num_ssts > 0)
    {
        (*iter)->sstables = malloc((size_t)num_ssts * sizeof(tidesdb_sstable_t *));
        if (!(*iter)->sstables)
        {
            pthread_rwlock_unlock(&cf->cf_lock);
            if ((*iter)->memtable_cursor) skip_list_cursor_free((*iter)->memtable_cursor);
            if ((*iter)->active_memtable) tidesdb_memtable_release((*iter)->active_memtable);
            if ((*iter)->immutable_memtables)
            {
                for (int i = 0; i < (*iter)->num_immutable_cursors; i++)
                {
                    if ((*iter)->immutable_memtable_cursors &&
                        (*iter)->immutable_memtable_cursors[i])
                    {
                        skip_list_cursor_free((*iter)->immutable_memtable_cursors[i]);
                    }
                    if ((*iter)->immutable_memtables[i])
                    {
                        tidesdb_memtable_release((*iter)->immutable_memtables[i]);
                    }
                }
                free((*iter)->immutable_memtables);
            }
            if ((*iter)->immutable_memtable_cursors) free((*iter)->immutable_memtable_cursors);
            free(*iter);
            return TDB_ERR_MEMORY;
        }

        /* snapshot all sstables atomically while holding lock */
        for (int i = 0; i < num_ssts; i++)
        {
            (*iter)->sstables[i] = cf->sstables[i];
            if (cf->sstables[i])
            {
                tidesdb_sstable_acquire(cf->sstables[i]);
            }
        }
    }
    pthread_rwlock_unlock(&cf->cf_lock);

    /* now set up cursors without holding the lock */
    if (num_ssts > 0)
    {
        (*iter)->sstable_cursors = malloc((size_t)num_ssts * sizeof(block_manager_cursor_t *));
        (*iter)->sstable_blocks_read = calloc((size_t)num_ssts, sizeof(int));
        if (!(*iter)->sstable_cursors || !(*iter)->sstable_blocks_read)
        {
            if ((*iter)->memtable_cursor) skip_list_cursor_free((*iter)->memtable_cursor);
            if ((*iter)->active_memtable) tidesdb_memtable_release((*iter)->active_memtable);
            if ((*iter)->immutable_memtables)
            {
                for (int i = 0; i < (*iter)->num_immutable_cursors; i++)
                {
                    if ((*iter)->immutable_memtable_cursors &&
                        (*iter)->immutable_memtable_cursors[i])
                    {
                        skip_list_cursor_free((*iter)->immutable_memtable_cursors[i]);
                    }
                    if ((*iter)->immutable_memtables[i])
                    {
                        tidesdb_memtable_release((*iter)->immutable_memtables[i]);
                    }
                }
                free((*iter)->immutable_memtables);
            }
            if ((*iter)->immutable_memtable_cursors) free((*iter)->immutable_memtable_cursors);
            /* release sstable references */
            for (int i = 0; i < num_ssts; i++)
            {
                if ((*iter)->sstables[i]) tidesdb_sstable_release((*iter)->sstables[i]);
            }
            if ((*iter)->sstable_cursors) free((*iter)->sstable_cursors);
            if ((*iter)->sstables) free((*iter)->sstables);
            if ((*iter)->sstable_blocks_read) free((*iter)->sstable_blocks_read);
            free(*iter);
            return TDB_ERR_MEMORY;
        }

        for (int i = 0; i < num_ssts; i++)
        {
            (*iter)->sstable_cursors[i] = NULL;
            (*iter)->sstable_blocks_read[i] = 0;
            if ((*iter)->sstables[i] && (*iter)->sstables[i]->block_manager)
            {
                block_manager_cursor_init(&(*iter)->sstable_cursors[i],
                                          (*iter)->sstables[i]->block_manager);
            }
        }
    }

    return 0;
}

int tidesdb_iter_seek_to_first(tidesdb_iter_t *iter)
{
    if (!iter) return TDB_ERR_INVALID_ARGS;

    iter->direction = 1;
    iter->valid = 0;

    /* clear existing heap */
    if (iter->heap)
    {
        for (int i = 0; i < iter->heap_size; i++)
        {
            if (iter->heap[i].key) free(iter->heap[i].key);
            if (iter->heap[i].value) free(iter->heap[i].value);
        }
        iter->heap_size = 0;
    }

    /* position memtable cursor BEFORE first element (at header) */
    if (iter->memtable_cursor)
    {
        skip_list_node_t *header =
            atomic_load_explicit(&iter->memtable_cursor->list->header, memory_order_acquire);
        skip_list_retain_node(header);
        if (iter->memtable_cursor->current) skip_list_release_node(iter->memtable_cursor->current);
        iter->memtable_cursor->current = header;
    }

    /* position immutable memtable cursors BEFORE first element */
    for (int i = 0; i < iter->num_immutable_cursors; i++)
    {
        if (iter->immutable_memtable_cursors[i])
        {
            skip_list_node_t *header = atomic_load_explicit(
                &iter->immutable_memtable_cursors[i]->list->header, memory_order_acquire);
            skip_list_retain_node(header);
            if (iter->immutable_memtable_cursors[i]->current)
                skip_list_release_node(iter->immutable_memtable_cursors[i]->current);
            iter->immutable_memtable_cursors[i]->current = header;
        }
    }

    /* position sstable cursors BEFORE first block */
    for (int i = 0; i < iter->num_sstable_cursors; i++)
    {
        if (iter->sstable_cursors[i])
        {
            iter->sstable_cursors[i]->current_pos = BLOCK_MANAGER_HEADER_SIZE;
            iter->sstable_cursors[i]->current_block_size = 0;
            iter->sstable_blocks_read[i] = 0;
        }
    }

    iter_refill_from_memtable(iter);
    for (int i = 0; i < iter->num_immutable_cursors; i++)
    {
        iter_refill_from_immutable(iter, i);
    }
    for (int i = 0; i < iter->num_sstable_cursors; i++)
    {
        iter_refill_from_sstable(iter, i);
    }

    /* get first entry (heap is already populated) */
    return tidesdb_iter_next(iter);
}

int tidesdb_iter_seek_to_last(tidesdb_iter_t *iter)
{
    if (!iter) return TDB_ERR_INVALID_ARGS;

    iter->direction = -1;
    iter->valid = 0;

    /* clear existing heap */
    if (iter->heap)
    {
        for (int i = 0; i < iter->heap_size; i++)
        {
            if (iter->heap[i].key) free(iter->heap[i].key);
            if (iter->heap[i].value) free(iter->heap[i].value);
        }
        iter->heap_size = 0;
    }

    /* position memtable cursor at last element */
    if (iter->memtable_cursor)
    {
        skip_list_cursor_goto_last(iter->memtable_cursor);
    }

    /* position immutable memtable cursors at last element */
    for (int i = 0; i < iter->num_immutable_cursors; i++)
    {
        if (iter->immutable_memtable_cursors[i])
        {
            skip_list_cursor_goto_last(iter->immutable_memtable_cursors[i]);
        }
    }

    /* position sstable cursors AFTER last KV block */
    for (int i = 0; i < iter->num_sstable_cursors; i++)
    {
        if (iter->sstable_cursors[i])
        {
            tidesdb_sstable_t *sst = iter->sstables[i];
            int num_entries = atomic_load(&sst->num_entries);
            if (sst && num_entries > 0)
            {
                block_manager_cursor_goto(iter->sstable_cursors[i], (uint64_t)(num_entries));
                iter->sstable_blocks_read[i] = num_entries;
            }
            else
            {
                block_manager_cursor_goto_last(iter->sstable_cursors[i]);
            }
        }
    }

    return tidesdb_iter_prev(iter);
}

int tidesdb_iter_seek(tidesdb_iter_t *iter, const uint8_t *key, size_t key_size)
{
    if (!iter || !key) return TDB_ERR_INVALID_ARGS;
    if (key_size == 0) return TDB_ERR_INVALID_ARGS; /* keys must have non-zero length */

    iter->direction = 1;
    iter->valid = 0;

    if (iter->current_key)
    {
        free(iter->current_key);
        iter->current_key = NULL;
    }
    if (iter->current_value)
    {
        free(iter->current_value);
        iter->current_value = NULL;
    }

    /* clear existing heap */
    if (iter->heap)
    {
        for (int i = 0; i < iter->heap_size; i++)
        {
            if (iter->heap[i].key) free(iter->heap[i].key);
            if (iter->heap[i].value) free(iter->heap[i].value);
        }
        iter->heap_size = 0;
    }

    /* position memtable cursor at or after target key */
    if (iter->memtable_cursor)
    {
        skip_list_cursor_seek(iter->memtable_cursor, key, key_size);
    }

    /* position immutable memtable cursors at or after target key */
    for (int i = 0; i < iter->num_immutable_cursors; i++)
    {
        if (iter->immutable_memtable_cursors[i])
        {
            skip_list_cursor_seek(iter->immutable_memtable_cursors[i], key, key_size);
        }
    }

    /* track which ssts were positioned by block index during this seek */
    int *index_positioned = calloc(iter->num_sstable_cursors, sizeof(int));
    if (!index_positioned) return TDB_ERR_MEMORY;

    /* position sstable cursors using min/max key optimization */
    for (int i = 0; i < iter->num_sstable_cursors; i++)
    {
        if (iter->sstable_cursors[i] && iter->sstables[i])
        {
            tidesdb_sstable_t *sst = iter->sstables[i];

            /* reset blocks_read for this seek */
            iter->sstable_blocks_read[i] = 0;

            /* check if target key is within this sstable's range */
            if (sst->min_key && sst->max_key)
            {
                int cmp_min =
                    compare_keys_with_cf(iter->cf, key, key_size, sst->min_key, sst->min_key_size);
                int cmp_max =
                    compare_keys_with_cf(iter->cf, key, key_size, sst->max_key, sst->max_key_size);

                if (cmp_max > 0)
                {
                    /* seek_key > max_key skip this entire sstable */
                    iter->sstable_blocks_read[i] = atomic_load(&sst->num_entries);
                }
                else if (cmp_min < 0)
                {
                    /* seek_key < min_key this ssts's first key is already >= seek_key
                     * no need to scan, just position at first block for heap population */
                    iter->sstable_cursors[i]->current_pos = BLOCK_MANAGER_HEADER_SIZE;
                    iter->sstable_cursors[i]->current_block_size = 0;
                    iter->sstable_blocks_read[i] = 0;
                    /* will be added to heap by iter_refill_from_sstable below */
                }
                else
                {
                    /* seek_key is within [min_key, max_key]
                     * try block index to jump directly to the key if it exists */
                    int positioned_via_index = 0;
                    if (sst->cf->config.enable_block_indexes && sst->index)
                    {
                        int64_t block_offset = -1;
                        if (succinct_trie_prefix_get(sst->index, (uint8_t *)key, key_size,
                                                     &block_offset) == 0)
                        {
                            positioned_via_index = 1;
                            index_positioned[i] = 1;
                            /* position cursor directly at byte offset */
                            iter->sstable_cursors[i]->current_pos = (uint64_t)block_offset;
                            iter->sstable_blocks_read[i] = -1; /* mark as positioned via index */
                        }
                    }

                    if (!positioned_via_index)
                    {
                        /* block index didn't find it, position at beginning */
                        iter->sstable_cursors[i]->current_pos = BLOCK_MANAGER_HEADER_SIZE;
                        iter->sstable_cursors[i]->current_block_size = 0;
                        iter->sstable_blocks_read[i] = 0;
                    }
                }
            }
            else
            {
                /* no min/max key info, start from beginning */
                iter->sstable_cursors[i]->current_pos = BLOCK_MANAGER_HEADER_SIZE;
                iter->sstable_cursors[i]->current_block_size = 0;
                iter->sstable_blocks_read[i] = 0;
            }
        }
    }

    /* populate heap with first entry >= key from each source */
    iter_refill_from_memtable(iter);
    for (int i = 0; i < iter->num_immutable_cursors; i++)
    {
        iter_refill_from_immutable(iter, i);
    }

    for (int i = 0; i < iter->num_sstable_cursors; i++)
    {
        tidesdb_sstable_t *sst = iter->sstables[i];
        if (!sst || !iter->sstable_cursors[i]) continue;

        int num_entries = atomic_load(&sst->num_entries);

        /* skip if out of range */
        if (iter->sstable_blocks_read[i] >= num_entries) continue;

        /* if block index positioned us, read the block directly */
        if (index_positioned[i])
        {
            /* cursor already positioned at byte offset, just read */
            block_manager_block_t *block = block_manager_cursor_read(iter->sstable_cursors[i]);
            if (block)
            {
                uint8_t *k = NULL, *v = NULL;
                size_t k_size = 0, v_size = 0;
                uint8_t deleted = 0;
                time_t ttl = 0;

                if (parse_block(block, iter->cf, &k, &k_size, &v, &v_size, &deleted, &ttl) == 0)
                {
                    if (!(ttl > 0 && time(NULL) > ttl) && !deleted)
                    {
                        tidesdb_iter_entry_t entry = {.key = k,
                                                      .key_size = k_size,
                                                      .value = v,
                                                      .value_size = v_size,
                                                      .deleted = deleted,
                                                      .ttl = ttl,
                                                      .source_type = 2,
                                                      .source_index = i};
                        heap_push(iter, &entry);
                    }
                    else
                    {
                        free(k);
                        free(v);
                    }
                }
                block_manager_block_free(block);
            }
            /* cursor is still at the indexed block we just read */
            /* set blocks_read = 1 so iter_refill will call cursor_next() to advance */
            iter->sstable_blocks_read[i] = 1;
            continue;
        }

        /* scan from current position to find first key >= seek_key */
        while (iter->sstable_blocks_read[i] < num_entries)
        {
            if (iter->sstable_blocks_read[i] == 0)
            {
                /* if cursor already positioned (e.g. by block index), don't reset it */
                if (iter->sstable_cursors[i]->current_pos == BLOCK_MANAGER_HEADER_SIZE)
                {
                    if (block_manager_cursor_goto_first(iter->sstable_cursors[i]) != 0) break;
                }
                /* else the cursor already positioned by block index, just read from current
                 * position */
            }
            else
            {
                if (block_manager_cursor_next(iter->sstable_cursors[i]) != 0) break;
            }

            /* check again after advancing cursor to prevent reading metadata blocks */
            if (iter->sstable_blocks_read[i] >= sst->num_entries) break;

            iter->sstable_blocks_read[i]++;

            block_manager_block_t *block = block_manager_cursor_read(iter->sstable_cursors[i]);
            if (!block) break;

            uint8_t *k = NULL, *v = NULL;
            size_t k_size = 0, v_size = 0;
            uint8_t deleted = 0;
            time_t ttl = 0;

            int parse_result =
                parse_block(block, iter->cf, &k, &k_size, &v, &v_size, &deleted, &ttl);
            block_manager_block_free(block);
            if (parse_result != 0) break;

            int cmp = compare_keys_with_cf(iter->cf, k, k_size, key, key_size);
            if (cmp >= 0)
            {
                /* found first key >= seek target */
                if (!(ttl > 0 && time(NULL) > ttl) && !deleted)
                {
                    tidesdb_iter_entry_t entry = {.key = k,
                                                  .key_size = k_size,
                                                  .value = v,
                                                  .value_size = v_size,
                                                  .deleted = deleted,
                                                  .ttl = ttl,
                                                  .source_type = 2,
                                                  .source_index = i};
                    heap_push(iter, &entry);
                }
                else
                {
                    free(k);
                    free(v);
                }
                break;
            }

            free(k);
            free(v);
        }
    }

    /* get first entry (heap is already populated) */
    free(index_positioned);
    return tidesdb_iter_next(iter);
}

int tidesdb_iter_seek_for_prev(tidesdb_iter_t *iter, const uint8_t *key, size_t key_size)
{
    if (!iter || !key) return TDB_ERR_INVALID_ARGS;
    if (key_size == 0) return TDB_ERR_INVALID_ARGS;

    iter->direction = -1;
    iter->valid = 0;

    /* free current key/value if they exist */
    if (iter->current_key)
    {
        free(iter->current_key);
        iter->current_key = NULL;
    }
    if (iter->current_value)
    {
        free(iter->current_value);
        iter->current_value = NULL;
    }

    /* clear existing heap */
    if (iter->heap)
    {
        for (int i = 0; i < iter->heap_size; i++)
        {
            if (iter->heap[i].key) free(iter->heap[i].key);
            if (iter->heap[i].value) free(iter->heap[i].value);
        }
        iter->heap_size = 0;
    }

    /* position memtable cursor at or before target key */
    if (iter->memtable_cursor)
    {
        skip_list_cursor_seek_for_prev(iter->memtable_cursor, key, key_size);
    }

    /* position immutable memtable cursors at or before target key */
    for (int i = 0; i < iter->num_immutable_cursors; i++)
    {
        if (iter->immutable_memtable_cursors[i])
        {
            skip_list_cursor_seek_for_prev(iter->immutable_memtable_cursors[i], key, key_size);
        }
    }

    /* track which ssts were positioned by block index during this seek */
    int *index_positioned = calloc(iter->num_sstable_cursors, sizeof(int));
    if (!index_positioned) return TDB_ERR_MEMORY;

    /* position sstable cursors using min/max key and block index optimization */
    for (int i = 0; i < iter->num_sstable_cursors; i++)
    {
        if (iter->sstable_cursors[i] && iter->sstables[i])
        {
            tidesdb_sstable_t *sst = iter->sstables[i];

            /* reset blocks_read for this seek */
            iter->sstable_blocks_read[i] = 0;

            /* check if target key is within this sstable's range */
            if (sst->min_key && sst->max_key)
            {
                int cmp_min =
                    compare_keys_with_cf(iter->cf, key, key_size, sst->min_key, sst->min_key_size);
                int cmp_max =
                    compare_keys_with_cf(iter->cf, key, key_size, sst->max_key, sst->max_key_size);

                /* if key < min_key, skip this sstable entirely */
                if (cmp_min < 0)
                {
                    /* no keys <= target in this sstable */
                    iter->sstable_blocks_read[i] = atomic_load(&sst->num_entries);
                    continue;
                }
                /* if key > max_key, position at end (all keys <= target) */ if (cmp_max > 0)
                {
                    /* start from end and scan backward */
                    iter->sstable_cursors[i]->current_pos = BLOCK_MANAGER_HEADER_SIZE;
                    iter->sstable_cursors[i]->current_block_size = 0;
                    iter->sstable_blocks_read[i] = 0;
                }
                /* key is within range, try block index for exact match */
                else
                {
                    int positioned_via_index = 0;
                    if (sst->cf->config.enable_block_indexes && sst->index)
                    {
                        int64_t block_offset = -1;
                        if (succinct_trie_prefix_get(sst->index, (uint8_t *)key, key_size,
                                                     &block_offset) == 0)
                        {
                            /* found exact key! position cursor at byte offset */
                            positioned_via_index = 1;
                            index_positioned[i] = 1;
                            iter->sstable_cursors[i]->current_pos = (uint64_t)block_offset;
                            iter->sstable_blocks_read[i] = -1; /* mark as positioned via index */
                        }
                    }

                    if (!positioned_via_index)
                    {
                        /* block index didn't find exact match, position at beginning for backward
                         * scan */
                        iter->sstable_cursors[i]->current_pos = BLOCK_MANAGER_HEADER_SIZE;
                        iter->sstable_cursors[i]->current_block_size = 0;
                        iter->sstable_blocks_read[i] = 0;
                    }
                }
            }
            else
            {
                /* no min/max key info, start from beginning */
                iter->sstable_cursors[i]->current_pos = BLOCK_MANAGER_HEADER_SIZE;
                iter->sstable_cursors[i]->current_block_size = 0;
                iter->sstable_blocks_read[i] = 0;
            }
        }
    }

    /* refill from immutable memtables */
    for (int i = 0; i < iter->num_immutable_cursors; i++)
    {
        iter_refill_from_immutable_backward(iter, i);
    }

    /* for sstables scan to find last key <= seek_key */
    for (int i = 0; i < iter->num_sstable_cursors; i++)
    {
        tidesdb_sstable_t *sst = iter->sstables[i];
        if (!sst) continue;

        int num_entries = atomic_load(&sst->num_entries);

        /* skip if already exhausted */
        if (iter->sstable_blocks_read[i] >= num_entries) continue;

        /* if block index positioned us at exact match, read block directly */
        if (index_positioned[i])
        {
            /* cursor already positioned at byte offset, just read */
            block_manager_block_t *block = block_manager_cursor_read(iter->sstable_cursors[i]);
            if (block)
            {
                uint8_t *k = NULL, *v = NULL;
                size_t k_size = 0, v_size = 0;
                uint8_t deleted = 0;
                time_t ttl = 0;

                if (parse_block(block, iter->cf, &k, &k_size, &v, &v_size, &deleted, &ttl) == 0)
                {
                    if (!(ttl > 0 && time(NULL) > ttl) && !deleted)
                    {
                        tidesdb_iter_entry_t entry = {.key = k,
                                                      .key_size = k_size,
                                                      .value = v,
                                                      .value_size = v_size,
                                                      .deleted = deleted,
                                                      .ttl = ttl,
                                                      .source_type = 2,
                                                      .source_index = i};
                        heap_push(iter, &entry);
                    }
                    else
                    {
                        free(k);
                        free(v);
                    }
                }
                block_manager_block_free(block);
            }
            /* cursor is still at the indexed block we just read */
            /* set blocks_read = 1 so iter_refill will call cursor_next() to advance */
            iter->sstable_blocks_read[i] = 1;
            continue;
        }

        /* scan forward to find last key <= seek_key */
        uint8_t *last_valid_key = NULL;
        size_t last_valid_key_size = 0;
        uint8_t *last_valid_value = NULL;
        size_t last_valid_value_size = 0;
        uint8_t last_valid_deleted = 0;
        time_t last_valid_ttl = 0;
        int found_any = 0;

        while (iter->sstable_blocks_read[i] < num_entries)
        {
            if (iter->sstable_blocks_read[i] == 0)
            {
                if (block_manager_cursor_goto_first(iter->sstable_cursors[i]) != 0) break;
            }
            else
            {
                if (block_manager_cursor_next(iter->sstable_cursors[i]) != 0) break;
            }

            /* check again after advancing cursor to prevent reading metadata blocks */
            if (iter->sstable_blocks_read[i] >= sst->num_entries) break;

            iter->sstable_blocks_read[i]++;

            block_manager_block_t *block = block_manager_cursor_read(iter->sstable_cursors[i]);
            if (!block) break;

            uint8_t *k = NULL, *v = NULL;
            size_t k_size = 0, v_size = 0;
            uint8_t deleted = 0;
            time_t ttl = 0;

            int parse_result =
                parse_block(block, iter->cf, &k, &k_size, &v, &v_size, &deleted, &ttl);
            block_manager_block_free(block);
            if (parse_result != 0) break;

            int cmp = compare_keys_with_cf(iter->cf, k, k_size, key, key_size);

            if (cmp <= 0)
            {
                /* this key <= target, save it as candidate */
                if (last_valid_key) free(last_valid_key);
                if (last_valid_value) free(last_valid_value);
                last_valid_key = k;
                last_valid_key_size = k_size;
                last_valid_value = v;
                last_valid_value_size = v_size;
                last_valid_deleted = deleted;
                last_valid_ttl = ttl;
                found_any = 1;
            }
            else
            {
                /* key > target, we've gone too far */
                free(k);
                free(v);
                break;
            }
        }

        /* add the last valid entry to heap if found */
        if (found_any)
        {
            if (!(last_valid_ttl > 0 && time(NULL) > last_valid_ttl) && !last_valid_deleted)
            {
                tidesdb_iter_entry_t entry = {.key = last_valid_key,
                                              .key_size = last_valid_key_size,
                                              .value = last_valid_value,
                                              .value_size = last_valid_value_size,
                                              .deleted = last_valid_deleted,
                                              .ttl = last_valid_ttl,
                                              .source_type = 2,
                                              .source_index = i};
                heap_push(iter, &entry);
            }
            else
            {
                free(last_valid_key);
                free(last_valid_value);
            }
        }
    }

    free(index_positioned);

    return tidesdb_iter_prev(iter);
}

int tidesdb_iter_next(tidesdb_iter_t *iter)
{
    if (!iter) return -1;

    iter->direction = 1;

    if (iter->current_key)
    {
        free(iter->current_key);
        iter->current_key = NULL;
    }
    if (iter->current_value)
    {
        free(iter->current_value);
        iter->current_value = NULL;
    }

    /* pop minimum entry from heap */
    tidesdb_iter_entry_t entry;
    if (heap_pop(iter, &entry) != 0)
    {
        iter->valid = 0;
        return -1;
    }

    /* refill heap from the source that produced this entry */
    if (entry.source_type == 0)
    {
        iter_refill_from_memtable(iter);
    }
    else if (entry.source_type == 1)
    {
        iter_refill_from_immutable(iter, entry.source_index);
    }
    else if (entry.source_type == 2)
    {
        iter_refill_from_sstable(iter, entry.source_index);
    }

    /* skip duplicate keys from other sources (keep newest version) */
    while (iter->heap_size > 0)
    {
        int cmp = compare_keys_with_cf(iter->cf, iter->heap[0].key, iter->heap[0].key_size,
                                       entry.key, entry.key_size);
        if (cmp != 0) break;

        tidesdb_iter_entry_t dup;
        heap_pop(iter, &dup);

        if (dup.source_type == 0)
        {
            iter_refill_from_memtable(iter);
        }
        else if (dup.source_type == 1)
        {
            iter_refill_from_immutable(iter, dup.source_index);
        }
        else if (dup.source_type == 2)
        {
            iter_refill_from_sstable(iter, dup.source_index);
        }

        free(dup.key);
        free(dup.value);
    }

    iter->current_key = entry.key;
    iter->current_key_size = entry.key_size;
    iter->current_value = entry.value;
    iter->current_value_size = entry.value_size;
    iter->current_deleted = entry.deleted;
    iter->valid = 1;

    return 0;
}

int tidesdb_iter_prev(tidesdb_iter_t *iter)
{
    if (!iter) return -1;

    iter->direction = -1;

    if (iter->current_key)
    {
        free(iter->current_key);
        iter->current_key = NULL;
    }
    if (iter->current_value)
    {
        free(iter->current_value);
        iter->current_value = NULL;
    }

    /* if heap is empty, populate it (first call after seek_to_last) */
    if (iter->heap_size == 0)
    {
        iter_refill_from_memtable_backward(iter);
        for (int i = 0; i < iter->num_immutable_cursors; i++)
        {
            iter_refill_from_immutable_backward(iter, i);
        }
        for (int i = 0; i < iter->num_sstable_cursors; i++)
        {
            iter_refill_from_sstable_backward(iter, i);
        }
    }

    /* pop maximum entry from heap (max-heap for backward iteration) */
    tidesdb_iter_entry_t entry;
    if (heap_pop(iter, &entry) != 0)
    {
        iter->valid = 0;
        return -1;
    }

    if (entry.source_type == 0)
    {
        iter_refill_from_memtable_backward(iter);
    }
    else if (entry.source_type == 1)
    {
        iter_refill_from_immutable_backward(iter, entry.source_index);
    }
    else if (entry.source_type == 2)
    {
        iter_refill_from_sstable_backward(iter, entry.source_index);
    }

    while (iter->heap_size > 0)
    {
        int cmp = compare_keys_with_cf(iter->cf, iter->heap[0].key, iter->heap[0].key_size,
                                       entry.key, entry.key_size);
        if (cmp != 0) break;

        tidesdb_iter_entry_t dup;
        heap_pop(iter, &dup);

        if (dup.source_type == 0)
        {
            iter_refill_from_memtable_backward(iter);
        }
        else if (dup.source_type == 1)
        {
            iter_refill_from_immutable_backward(iter, dup.source_index);
        }
        else if (dup.source_type == 2)
        {
            iter_refill_from_sstable_backward(iter, dup.source_index);
        }

        free(dup.key);
        free(dup.value);
    }

    iter->current_key = entry.key;
    iter->current_key_size = entry.key_size;
    iter->current_value = entry.value;
    iter->current_value_size = entry.value_size;
    iter->current_deleted = entry.deleted;
    iter->valid = 1;

    return 0;
}

int tidesdb_iter_valid(tidesdb_iter_t *iter)
{
    if (!iter) return 0;
    return iter->valid;
}

int tidesdb_iter_key(tidesdb_iter_t *iter, uint8_t **key, size_t *key_size)
{
    if (!iter || !iter->valid || !key || !key_size) return -1;

    *key = iter->current_key;
    *key_size = iter->current_key_size;
    return 0;
}

int tidesdb_iter_value(tidesdb_iter_t *iter, uint8_t **value, size_t *value_size)
{
    if (!iter || !iter->valid || !value || !value_size) return -1;

    if (iter->current_deleted) return -1;

    *value = iter->current_value;
    *value_size = iter->current_value_size;
    return 0;
}

void tidesdb_iter_free(tidesdb_iter_t *iter)
{
    if (!iter) return;

    if (iter->current_key) free(iter->current_key);
    if (iter->current_value) free(iter->current_value);
    if (iter->memtable_cursor)
    {
        skip_list_cursor_free(iter->memtable_cursor);
    }
    if (iter->active_memtable)
    {
        tidesdb_memtable_release(iter->active_memtable);
    }

    if (iter->immutable_memtable_cursors)
    {
        for (int i = 0; i < iter->num_immutable_cursors; i++)
        {
            if (iter->immutable_memtable_cursors[i])
            {
                skip_list_cursor_free(iter->immutable_memtable_cursors[i]);
            }
            if (iter->immutable_memtables && iter->immutable_memtables[i])
            {
                tidesdb_memtable_release(iter->immutable_memtables[i]);
            }
        }
        free(iter->immutable_memtable_cursors);
    }

    if (iter->immutable_memtables)
    {
        free(iter->immutable_memtables);
    }

    if (iter->sstable_cursors)
    {
        for (int i = 0; i < iter->num_sstable_cursors; i++)
        {
            if (iter->sstable_cursors[i])
            {
                block_manager_cursor_free(iter->sstable_cursors[i]);
            }
            if (iter->sstables && iter->sstables[i])
            {
                tidesdb_sstable_release(iter->sstables[i]);
            }
        }
        free(iter->sstable_cursors);
    }

    if (iter->sstables) free(iter->sstables);
    if (iter->sstable_blocks_read) free(iter->sstable_blocks_read);

    if (iter->heap)
    {
        for (int i = 0; i < iter->heap_size; i++)
        {
            if (iter->heap[i].key) free(iter->heap[i].key);
            if (iter->heap[i].value) free(iter->heap[i].value);
        }
        free(iter->heap);
    }

    free(iter);
}