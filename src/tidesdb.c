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

/* global debug logging flag */
int _tidesdb_debug_enabled = 0;

/* comparator registry */
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

/* forward declarations for static functions */
static int tidesdb_load_sstable(tidesdb_column_family_t *cf, uint64_t sstable_id,
                                tidesdb_sstable_t **sstable);
static void tidesdb_sstable_free(tidesdb_sstable_t *sstable);
static int tidesdb_check_and_flush(tidesdb_column_family_t *cf);
static void *tidesdb_background_compaction_thread(void *arg);
static tidesdb_memtable_t *tidesdb_memtable_new(tidesdb_column_family_t *cf);
static void tidesdb_memtable_free(tidesdb_memtable_t *mt);
static int tidesdb_rotate_memtable(tidesdb_column_family_t *cf);
static void *tidesdb_flush_worker_thread(void *arg);
static int tidesdb_flush_memtable_to_sstable(tidesdb_column_family_t *cf, tidesdb_memtable_t *mt);
static int compare_keys_with_cf(tidesdb_column_family_t *cf, const uint8_t *key1, size_t key1_size,
                                const uint8_t *key2, size_t key2_size);
static int parse_block(block_manager_block_t *block, tidesdb_column_family_t *cf, uint8_t **key,
                       size_t *key_size, uint8_t **value, size_t *value_size, uint8_t *deleted,
                       time_t *ttl);
static void get_sstable_path(const tidesdb_column_family_t *cf, uint64_t sstable_id, char *path);

/* reference counting helpers for sstables */
static inline void tidesdb_sstable_acquire(tidesdb_sstable_t *sst)
{
    if (sst)
    {
        atomic_fetch_add(&sst->ref_count, 1);
    }
}

static inline int tidesdb_sstable_release(tidesdb_sstable_t *sst)
{
    if (!sst) return 0;
    int old_count = atomic_fetch_sub(&sst->ref_count, 1);
    int new_count = old_count - 1;

    /* if ref_count dropped to 0, free the sstable structure (but NOT the file) */
    if (new_count == 0)
    {
        tidesdb_sstable_free(sst);
    }

    return new_count;
}

static inline int tidesdb_sstable_get_ref_count(tidesdb_sstable_t *sst)
{
    if (!sst) return 0;
    return atomic_load(&sst->ref_count);
}

/* reference counting helpers for memtables */
static inline void tidesdb_memtable_acquire(tidesdb_memtable_t *mt)
{
    if (mt)
    {
        atomic_fetch_add(&mt->ref_count, 1);
    }
}

/* heap helper functions for iterator merge */
static void heap_swap(tidesdb_iter_entry_t *heap, int i, int j)
{
    tidesdb_iter_entry_t temp = heap[i];
    heap[i] = heap[j];
    heap[j] = temp;
}

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
            int cmp =
                compare_keys_with_cf(iter->cf, iter->heap[left].key, iter->heap[left].key_size,
                                     iter->heap[best].key, iter->heap[best].key_size);
            if (forward ? (cmp < 0) : (cmp > 0)) best = left;
        }

        if (right < size)
        {
            int cmp =
                compare_keys_with_cf(iter->cf, iter->heap[right].key, iter->heap[right].key_size,
                                     iter->heap[best].key, iter->heap[best].key_size);
            if (forward ? (cmp < 0) : (cmp > 0)) best = right;
        }

        if (best == idx) break;

        heap_swap(iter->heap, idx, best);
        idx = best;
    }
}

static void heap_sift_up(tidesdb_iter_t *iter, int idx)
{
    int forward = (iter->direction > 0);

    while (idx > 0)
    {
        int parent = (idx - 1) / 2;
        int cmp = compare_keys_with_cf(iter->cf, iter->heap[idx].key, iter->heap[idx].key_size,
                                       iter->heap[parent].key, iter->heap[parent].key_size);
        if (forward ? (cmp >= 0) : (cmp <= 0)) break;

        heap_swap(iter->heap, idx, parent);
        idx = parent;
    }
}

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

/* helper to read next entry from active memtable and add to heap */
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
        if (deleted) continue; /* skip tombstones */

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
            return heap_push(iter, &entry);
        }
        else
        {
            if (entry.key) free(entry.key);
            if (entry.value) free(entry.value);
            return -1;
        }
    }
    return 0;
}

/* helper to read next entry from immutable memtable and add to heap */
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
        if (deleted) continue; /* skip tombstones */

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
        else
        {
            if (entry.key) free(entry.key);
            if (entry.value) free(entry.value);
            return -1;
        }
    }
    return 0;
}

/* helper to read next entry from sstable and add to heap */
static int iter_refill_from_sstable(tidesdb_iter_t *iter, int idx)
{
    if (idx >= iter->num_sstable_cursors || !iter->sstable_cursors[idx]) return 0;

    tidesdb_sstable_t *sst = iter->sstables[idx];
    if (sst && iter->sstable_blocks_read[idx] >= sst->num_entries) return 0;

    while (block_manager_cursor_has_next(iter->sstable_cursors[idx]))
    {
        if (sst && iter->sstable_blocks_read[idx] >= sst->num_entries) break;

        /* position at first block or advance to next */
        if (iter->sstable_blocks_read[idx] == 0)
        {
            if (block_manager_cursor_goto_first(iter->sstable_cursors[idx]) != 0) break;
        }
        else
        {
            if (block_manager_cursor_next(iter->sstable_cursors[idx]) != 0) break;
        }
        iter->sstable_blocks_read[idx]++;

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
            continue; /* skip expired */
        }

        if (deleted)
        {
            free(k);
            free(v);
            continue; /* skip tombstones */
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

/* helper to read previous entry from active memtable (for backward iteration) */
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
                /* skip expired, move backward and return */
                skip_list_cursor_prev(iter->memtable_cursor);
                return 0;
            }
            
            if (deleted)
            {
                /* skip tombstones, move backward and return */
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
            else
            {
                if (entry.key) free(entry.key);
                if (entry.value) free(entry.value);
                return -1;
            }
        }
    }
    return 0;
}

/* helper to read previous entry from immutable memtable (for backward iteration) */
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
            else
            {
                if (entry.key) free(entry.key);
                if (entry.value) free(entry.value);
                return -1;
            }
        }
    }
    return 0;
}

/* helper to read previous entry from sstable (for backward iteration) */
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
        /* position at last block or move to previous */
        if (sst && iter->sstable_blocks_read[idx] == sst->num_entries)
        {
            /* first read after seek_to_last, go to last KV block (0-indexed) */

            if (block_manager_cursor_goto(iter->sstable_cursors[idx],
                                          (uint64_t)(sst->num_entries - 1)) != 0)
            {
                return 0;
            }
            iter->sstable_blocks_read[idx] = sst->num_entries - 1;
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
            return 0; /* skip expired */
        }
        
        if (deleted)
        {
            free(k);
            free(v);
            return 0; /* skip tombstones */
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

static inline int tidesdb_memtable_release(tidesdb_memtable_t *mt)
{
    if (!mt) return 0;
    int old_count = atomic_fetch_sub(&mt->ref_count, 1);
    return old_count - 1; /* return new count */
}

static inline int tidesdb_memtable_get_ref_count(tidesdb_memtable_t *mt)
{
    if (!mt) return 0;
    return atomic_load(&mt->ref_count);
}

tidesdb_column_family_config_t tidesdb_default_column_family_config(void)
{
    tidesdb_column_family_config_t config = {
        .memtable_flush_size = TDB_DEFAULT_MEMTABLE_FLUSH_SIZE,
        .max_sstables_before_compaction = TDB_DEFAULT_MAX_SSTABLES,
        .compaction_threads = TDB_DEFAULT_COMPACTION_THREADS,
        .max_level = TDB_DEFAULT_SKIPLIST_LEVELS,
        .probability = TDB_DEFAULT_SKIPLIST_PROBABILITY,
        .compressed = 1,
        .compress_algo = COMPRESS_LZ4,
        .bloom_filter_fp_rate = TDB_DEFAULT_BLOOM_FILTER_FP_RATE,
        .enable_background_compaction = 1,
        .background_compaction_interval = TDB_DEFAULT_BACKGROUND_COMPACTION_INTERVAL,
        .use_sbha = 1,
        .sync_mode = TDB_SYNC_BACKGROUND,
        .sync_interval = 1,
        .comparator_name = NULL};
    return config;
}

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

static void get_cf_path(const tidesdb_t *db, const char *cf_name, char *path)
{
    (void)snprintf(path, TDB_MAX_PATH_LENGTH, "%s" PATH_SEPARATOR "%s", db->config.db_path,
                   cf_name);
}

static void get_wal_path(const tidesdb_column_family_t *cf, char *path)
{
    char cf_path[TDB_MAX_PATH_LENGTH];
    get_cf_path(cf->db, cf->name, cf_path);
    (void)snprintf(path, TDB_MAX_PATH_LENGTH, "%s" PATH_SEPARATOR "wal%s", cf_path, TDB_WAL_EXT);
}

static void get_sstable_path(const tidesdb_column_family_t *cf, uint64_t sstable_id, char *path)
{
    char cf_path[TDB_MAX_PATH_LENGTH];
    get_cf_path(cf->db, cf->name, cf_path);
    (void)snprintf(path, TDB_MAX_PATH_LENGTH, "%s" PATH_SEPARATOR "sstable_%llu%s", cf_path,
                   (unsigned long long)sstable_id, TDB_SSTABLE_EXT);
}

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

static block_manager_t *get_cached_block_manager(tidesdb_t *db, const char *path,
                                                 tidesdb_sync_mode_t sync_mode, int sync_interval)
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

    if (block_manager_open(&bm, path, sync_mode, sync_interval) == -1)
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
    (*db)->column_families = NULL;
    (*db)->num_cfs = 0;
    (*db)->cf_capacity = 0;
    (*db)->block_manager_cache = NULL;

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

#ifdef _WIN32
            char entry_path[TDB_MAX_PATH_LENGTH];
            (void)snprintf(entry_path, TDB_MAX_PATH_LENGTH, "%s" PATH_SEPARATOR "%s",
                           config->db_path, entry->d_name);
            struct stat st;
            if (stat(entry_path, &st) == 0 && S_ISDIR(st.st_mode))
#else
            if (entry->d_type == DT_DIR)
#endif
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

    pthread_rwlock_wrlock(&db->db_lock);

    for (int i = 0; i < db->num_cfs; i++)
    {
        tidesdb_column_family_t *cf = db->column_families[i];
        if (!cf) continue;


        atomic_store(&cf->flush_stop, 1);
        
        /* wake up flush thread if waiting */
        tidesdb_memtable_t *dummy = NULL;
        queue_enqueue(cf->flush_queue, dummy);
        pthread_join(cf->flush_thread, NULL);

        /* flush any remaining immutable memtables */
        tidesdb_memtable_t *mt;
        while ((mt = (tidesdb_memtable_t *)queue_dequeue(cf->immutable_memtables)) != NULL)
        {
            tidesdb_flush_memtable_to_sstable(cf, mt);
            tidesdb_memtable_free(mt);
        }

        /* stop compaction thread */
        if (cf->config.enable_background_compaction)
        {
            atomic_store(&cf->compaction_stop, 1);
            pthread_join(cf->compaction_thread, NULL);
        }

        /* force close active memtable WAL and free */
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
        if (cf->flush_queue) queue_free(cf->flush_queue);

        /* force-free all SSTables */
        for (int j = 0; j < cf->num_sstables; j++)
        {
            if (cf->sstables[j])
            {
                tidesdb_sstable_t *sst = cf->sstables[j];
                if (sst->index) binary_hash_array_free(sst->index);
                if (sst->bloom_filter) bloom_filter_free(sst->bloom_filter);
                pthread_mutex_destroy(&sst->ref_lock);
                free(sst);
            }
        }
        free(cf->sstables);

        pthread_rwlock_destroy(&cf->cf_lock);
        pthread_mutex_destroy(&cf->flush_lock);
        pthread_mutex_destroy(&cf->compaction_lock);
        free(cf);
    }

    free(db->column_families);

    /* close all cached block managers before destroying cache
     * we use lru_cache_free which calls eviction callbacks to properly close them */
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
    atomic_init(&cf->flush_stop, 0);
    atomic_init(&cf->compaction_stop, 0);
    atomic_init(&cf->is_dropping, 0);
    cf->flush_queue = NULL;
    memset(&cf->cf_lock, 0, sizeof(pthread_rwlock_t));
    memset(&cf->flush_lock, 0, sizeof(pthread_mutex_t));
    memset(&cf->flush_thread, 0, sizeof(pthread_t));
    memset(&cf->compaction_lock, 0, sizeof(pthread_mutex_t));
    memset(&cf->compaction_thread, 0, sizeof(pthread_t));

    if (config)
    {
        memcpy(&cf->config, config, sizeof(tidesdb_column_family_config_t));
    }
    else
    {
        cf->config = tidesdb_default_column_family_config();
    }

    /* lookup comparator by name */
    const char *cmp_name = cf->config.comparator_name ? cf->config.comparator_name : "memcmp";
    skip_list_comparator_fn cmp_fn = tidesdb_get_comparator(cmp_name);

    if (!cmp_fn)
    {
        TDB_DEBUG_LOG("Comparator '%s' not found in registry", cmp_name);
        free(cf);
        pthread_rwlock_unlock(&db->db_lock);
        return TDB_ERR_COMPARATOR_NOT_FOUND;
    }

    /* save comparator name */
    strncpy(cf->comparator_name, cmp_name, TDB_MAX_COMPARATOR_NAME - 1);
    cf->comparator_name[TDB_MAX_COMPARATOR_NAME - 1] = '\0';

    TDB_DEBUG_LOG("Column family '%s' using comparator '%s'", name, cf->comparator_name);

    /* initialize locks */
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

    char cf_path[TDB_MAX_PATH_LENGTH];
    get_cf_path(db, name, cf_path);
    if (mkdir_p(cf_path) == -1)
    {
        pthread_rwlock_destroy(&cf->cf_lock);
        pthread_mutex_destroy(&cf->flush_lock);
        pthread_mutex_destroy(&cf->compaction_lock);
        free(cf);
        pthread_rwlock_unlock(&db->db_lock);
        return TDB_ERR_IO;
    }

    /* initialize memtable IDs */
    atomic_store(&cf->next_memtable_id, 0);
    atomic_store(&cf->flush_stop, 0);

    /* create queues */
    cf->immutable_memtables = queue_new();
    cf->flush_queue = queue_new();
    if (!cf->immutable_memtables || !cf->flush_queue)
    {
        if (cf->immutable_memtables) queue_free(cf->immutable_memtables);
        if (cf->flush_queue) queue_free(cf->flush_queue);
        pthread_rwlock_destroy(&cf->cf_lock);
        pthread_mutex_destroy(&cf->flush_lock);
        pthread_mutex_destroy(&cf->compaction_lock);
        free(cf);
        pthread_rwlock_unlock(&db->db_lock);
        return TDB_ERR_MEMORY;
    }

    /* create initial active memtable */
    tidesdb_memtable_t *initial_mt = tidesdb_memtable_new(cf);
    if (!initial_mt)
    {
        queue_free(cf->immutable_memtables);
        queue_free(cf->flush_queue);
        pthread_rwlock_destroy(&cf->cf_lock);
        pthread_mutex_destroy(&cf->flush_lock);
        pthread_mutex_destroy(&cf->compaction_lock);
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
            if (strstr(entry->d_name, "wal_") && strstr(entry->d_name, ".log"))
            {
                /* parse WAL ID */
                const char *id_start = entry->d_name + 4; /* skip "wal_" */
                char *endptr;
                uint64_t wal_id = strtoul(id_start, &endptr, 10);
                if (endptr != id_start && strstr(endptr, ".log"))
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
        recovered_mt->created_at = time(NULL);

        skip_list_comparator_fn cmp_fn = tidesdb_get_comparator(cf->comparator_name);
        if (skip_list_new_with_comparator(&recovered_mt->memtable, cf->config.max_level,
                                          cf->config.probability, cmp_fn, NULL) == -1)
        {
            free(recovered_mt);
            continue;
        }

        /* open WAL file directly (not cached) */
        if (block_manager_open(&recovered_mt->wal, wal_files[i].path, cf->config.sync_mode,
                               cf->config.sync_interval) == -1)
        {
            skip_list_free(recovered_mt->memtable);
            free(recovered_mt);
            continue;
        }

        /* recover entries from WAL into memtable */
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
                        if (block->size >= sizeof(tidesdb_kv_pair_header_t))
                        {
                            tidesdb_kv_pair_header_t header;
                            memcpy(&header, block->data, sizeof(tidesdb_kv_pair_header_t));

                            uint8_t *data_ptr = (uint8_t *)block->data;
                            uint8_t *key = data_ptr + sizeof(tidesdb_kv_pair_header_t);
                            uint8_t *value = key + header.key_size;

                            if (header.flags & TDB_KV_FLAG_TOMBSTONE)
                            {
                                /* tombstone */
                                uint8_t empty = 0;
                                skip_list_put(recovered_mt->memtable, key, header.key_size, &empty,
                                              0, 0);
                                skip_list_delete(recovered_mt->memtable, key, header.key_size);
                            }
                            else
                            {
                                /* normal entry */
                                skip_list_put(recovered_mt->memtable, key, header.key_size, value,
                                              header.value_size, (time_t)header.ttl);
                            }
                        }
                        block_manager_block_free(block);
                    }
                } while (block_manager_cursor_next(cursor) == 0);
            }
            block_manager_cursor_free(cursor);
        }

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
            queue_enqueue(cf->flush_queue, recovered_mt);
        }
    }

    if (wal_files) free(wal_files);

    /* release db_lock before starting threads to avoid deadlock */
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
                /* parse sstable ID using strtoul for safer conversion */
                const char *id_start = entry->d_name + 8; /* skip "sstable_" */
                char *endptr;
                uint64_t sstable_id = strtoul(id_start, &endptr, 10);
                if (endptr != id_start && strstr(endptr, ".sst"))
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
                    }
                }
            }
        }
        closedir(dir);
    }

    /* start flush worker thread */
    if (pthread_create(&cf->flush_thread, NULL, tidesdb_flush_worker_thread, cf) != 0)
    {
        tidesdb_memtable_t *active_mt = atomic_load(&cf->active_memtable);
        tidesdb_memtable_free(active_mt);
        queue_free(cf->immutable_memtables);
        queue_free(cf->flush_queue);
        pthread_rwlock_destroy(&cf->cf_lock);
        pthread_mutex_destroy(&cf->flush_lock);
        pthread_mutex_destroy(&cf->compaction_lock);
        free(cf);
        return TDB_ERR_THREAD;
    }

    /* start background compaction thread if enabled */
    if (cf->config.enable_background_compaction)
    {
        if (pthread_create(&cf->compaction_thread, NULL, tidesdb_background_compaction_thread,
                           cf) != 0)
        {
            /* failed to create compaction thread; stop flush thread and cleanup */
            cf->config.enable_background_compaction = 0;

    
            atomic_store(&cf->flush_stop, 1);
            tidesdb_memtable_t *dummy = NULL;
            queue_enqueue(cf->flush_queue, dummy);
            pthread_join(cf->flush_thread, NULL);

    
            tidesdb_memtable_t *active_mt = atomic_load(&cf->active_memtable);
            if (active_mt) tidesdb_memtable_free(active_mt);
            if (cf->immutable_memtables) queue_free(cf->immutable_memtables);
            if (cf->flush_queue) queue_free(cf->flush_queue);

            pthread_rwlock_destroy(&cf->cf_lock);
            pthread_mutex_destroy(&cf->flush_lock);
            pthread_mutex_destroy(&cf->compaction_lock);
            free(cf);
            return TDB_ERR_THREAD;
        }
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
            atomic_store(&cf->flush_stop, 1);
            tidesdb_memtable_t *dummy = NULL;
            queue_enqueue(cf->flush_queue, dummy);
            pthread_join(cf->flush_thread, NULL);

            tidesdb_memtable_t *active_mt = atomic_load(&cf->active_memtable);
            if (active_mt) tidesdb_memtable_free(active_mt);
            if (cf->immutable_memtables) queue_free(cf->immutable_memtables);
            if (cf->flush_queue) queue_free(cf->flush_queue);

            pthread_rwlock_destroy(&cf->cf_lock);
            pthread_mutex_destroy(&cf->flush_lock);
            pthread_mutex_destroy(&cf->compaction_lock);
            free(cf);
            /* db_lock already released at line 1230, don't unlock again */
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

    /* OPTION 3: Mark CF as dropping to prevent new operations */
    atomic_store(&cf->is_dropping, 1);

    /* stop flush thread */
    atomic_store(&cf->flush_stop, 1);
    
    /* wake up flush thread if waiting */
    tidesdb_memtable_t *dummy = NULL;
    queue_enqueue(cf->flush_queue, dummy);
    if (pthread_join(cf->flush_thread, NULL) != 0)
    {
        cleanup_error = TDB_ERR_THREAD;
    }

    /* stop background compaction thread if running */
    if (cf->config.enable_background_compaction)
    {
        atomic_store(&cf->compaction_stop, 1);
        if (pthread_join(cf->compaction_thread, NULL) != 0)
        {
            cleanup_error = TDB_ERR_THREAD;
            /* continue with cleanup anyway */
        }
    }

    /* OPTION 1: Force close WAL files regardless of ref_count */
    /* This ensures file handles are released even if iterators/txns still hold references */
    
    /* force close active memtable WAL (no lock needed - threads are stopped) */
    tidesdb_memtable_t *active_mt = atomic_load(&cf->active_memtable);
    if (active_mt)
    {
        if (active_mt->wal)
        {
            block_manager_close(active_mt->wal);
            active_mt->wal = NULL;
        }
    }

    /* force close immutable memtable WALs */
    if (cf->immutable_memtables)
    {
        pthread_mutex_lock(&cf->flush_lock);
        size_t queue_len = queue_size(cf->immutable_memtables);
        for (size_t i = 0; i < queue_len; i++)
        {
            tidesdb_memtable_t *mt = (tidesdb_memtable_t *)queue_peek_at(cf->immutable_memtables, i);
            if (mt && mt->wal)
            {
                block_manager_close(mt->wal);
                mt->wal = NULL;
            }
        }
        pthread_mutex_unlock(&cf->flush_lock);
    }

    /* NOW free memtables (WALs already closed, so tidesdb_memtable_free won't try to close them again) */
    if (active_mt)
    {
        tidesdb_memtable_free(active_mt);
    }

    /* free immutable memtables */
    if (cf->immutable_memtables)
    {
        tidesdb_memtable_t *mt;
        while ((mt = (tidesdb_memtable_t *)queue_dequeue(cf->immutable_memtables)) != NULL)
        {
            tidesdb_memtable_free(mt);
        }
        queue_free(cf->immutable_memtables);
    }

    /* free flush queue */
    if (cf->flush_queue) queue_free(cf->flush_queue);

    /* force-free all SSTables (evict from cache and free structures) */
    for (int i = 0; i < cf->num_sstables; i++)
    {
        if (cf->sstables[i])
        {
            char path[TDB_MAX_PATH_LENGTH];
            get_sstable_path(cf, cf->sstables[i]->id, path);

            /* evict from cache (closes the file handle) */
            if (db->block_manager_cache)
            {
                lru_cache_remove(db->block_manager_cache, path);
            }

            /* force-free SSTable structure regardless of ref_count */
            tidesdb_sstable_t *sst = cf->sstables[i];
            if (sst->index) binary_hash_array_free(sst->index);
            if (sst->bloom_filter) bloom_filter_free(sst->bloom_filter);
            pthread_mutex_destroy(&sst->ref_lock);
            free(sst);
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
                    /* delete file (WAL, SSTable, config, temp, etc.) */
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
        strncpy((*names)[i], db->column_families[i]->name, TDB_MAX_CF_NAME_LENGTH - 1);
        (*names)[i][TDB_MAX_CF_NAME_LENGTH - 1] = '\0';
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

    /* alloc stats struct */
    *stats = malloc(sizeof(tidesdb_column_family_stat_t));
    if (!*stats) return TDB_ERR_MEMORY;

    pthread_rwlock_rdlock(&cf->cf_lock);

    /* copy basic info */
    strncpy((*stats)->name, cf->name, TDB_MAX_CF_NAME_LENGTH - 1);
    (*stats)->name[TDB_MAX_CF_NAME_LENGTH - 1] = '\0';

    strncpy((*stats)->comparator_name, cf->comparator_name, TDB_MAX_COMPARATOR_NAME - 1);
    (*stats)->comparator_name[TDB_MAX_COMPARATOR_NAME - 1] = '\0';

    /* sst stats */
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

static tidesdb_memtable_t *tidesdb_memtable_new(tidesdb_column_family_t *cf)
{
    if (!cf) return NULL;

    tidesdb_memtable_t *mt = malloc(sizeof(tidesdb_memtable_t));
    if (!mt) return NULL;

    mt->id = atomic_fetch_add(&cf->next_memtable_id, 1);
    mt->created_at = time(NULL);
    atomic_store(&mt->ref_count, 1); /* initial reference for active memtable */
    
    if (pthread_mutex_init(&mt->ref_lock, NULL) != 0)
    {
        free(mt);
        return NULL;
    }

    skip_list_comparator_fn cmp_fn = tidesdb_get_comparator(cf->comparator_name);
    if (skip_list_new_with_comparator(&mt->memtable, cf->config.max_level, cf->config.probability,
                                      cmp_fn, NULL) == -1)
    {
        pthread_mutex_destroy(&mt->ref_lock);
        free(mt);
        return NULL;
    }

    char wal_path[TDB_MAX_PATH_LENGTH];
    snprintf(wal_path, sizeof(wal_path), "%s" PATH_SEPARATOR "%s" PATH_SEPARATOR "wal_%lu.log",
             cf->db->config.db_path, cf->name, mt->id);

    if (block_manager_open(&mt->wal, wal_path, cf->config.sync_mode, cf->config.sync_interval) ==
        -1)
    {
        skip_list_free(mt->memtable);
        pthread_mutex_destroy(&mt->ref_lock);
        free(mt);
        return NULL;
    }

    return mt;
}

static void tidesdb_memtable_free(tidesdb_memtable_t *mt)
{
    if (!mt) return;

    /* decrement reference count and only free if it reaches 0 */
    int ref_count = tidesdb_memtable_release(mt);
    if (ref_count > 0)
    {
        /* still has references, don't free yet */
        return;
    }
    
    if (ref_count < 0)
    {
        return;
    }

    /* ref_count is 0, safe to free */
    if (mt->memtable) skip_list_free(mt->memtable);
    if (mt->wal) block_manager_close(mt->wal);
    pthread_mutex_destroy(&mt->ref_lock);
    free(mt);
}

static int tidesdb_rotate_memtable(tidesdb_column_family_t *cf)
{
    if (!cf) return -1;

    tidesdb_memtable_t *new_memtable = tidesdb_memtable_new(cf);
    if (!new_memtable) return -1;

    tidesdb_memtable_t *old_memtable = atomic_exchange(&cf->active_memtable, new_memtable);

    /* enqueue old memtable for flushing */
    if (old_memtable)
    {
        pthread_mutex_lock(&cf->flush_lock);
        queue_enqueue(cf->immutable_memtables, old_memtable);
        queue_enqueue(cf->flush_queue, old_memtable);
        pthread_mutex_unlock(&cf->flush_lock);
    }

    return 0;
}

static int tidesdb_flush_memtable_to_sstable(tidesdb_column_family_t *cf, tidesdb_memtable_t *mt)
{
    if (!cf || !mt) return -1;

    TDB_DEBUG_LOG("Flushing memtable %lu for column family: %s", mt->id, cf->name);

    if (skip_list_count_entries(mt->memtable) == 0)
    {
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
    atomic_store(&sst->ref_count, 1);
    pthread_mutex_init(&sst->ref_lock, NULL);

    sst->block_manager = get_cached_block_manager(cf->db, sstable_path, cf->config.sync_mode,
                                                  cf->config.sync_interval);
    if (!sst->block_manager)
    {
        free(sst);
        return -1;
    }

    int num_entries = skip_list_count_entries(mt->memtable);
    bloom_filter_new(&sst->bloom_filter, cf->config.bloom_filter_fp_rate, num_entries);
    sst->index = binary_hash_array_new((size_t)num_entries);

    skip_list_cursor_t *cursor = skip_list_cursor_init(mt->memtable);
    if (cursor)
    {
        skip_list_node_t *header =
            atomic_load_explicit(&mt->memtable->header, memory_order_acquire);
        skip_list_retain_node(header);
        if (cursor->current) skip_list_release_node(cursor->current);
        cursor->current = header;

        while (skip_list_cursor_has_next(cursor))
        {
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
                    if (sst->min_key)
                    {
                        memcpy(sst->min_key, k, k_size);
                        sst->min_key_size = k_size;
                    }
                }

                if (sst->max_key) free(sst->max_key);
                sst->max_key = malloc(k_size);
                if (sst->max_key)
                {
                    memcpy(sst->max_key, k, k_size);
                    sst->max_key_size = k_size;
                }

                tidesdb_kv_pair_header_t header = {.version = TDB_KV_FORMAT_VERSION,
                                                   .flags = deleted ? TDB_KV_FLAG_TOMBSTONE : 0,
                                                   .key_size = (uint32_t)k_size,
                                                   .value_size = (uint32_t)v_size,
                                                   .ttl = (int64_t)ttl};

                size_t block_size = sizeof(tidesdb_kv_pair_header_t) + k_size + v_size;
                uint8_t *block_data = malloc(block_size);
                if (block_data)
                {
                    uint8_t *ptr = block_data;
                    memcpy(ptr, &header, sizeof(tidesdb_kv_pair_header_t));
                    ptr += sizeof(tidesdb_kv_pair_header_t);
                    memcpy(ptr, k, k_size);
                    ptr += k_size;
                    memcpy(ptr, v, v_size);

                    uint8_t *final_data = block_data;
                    size_t final_size = block_size;

                    if (cf->config.compressed)
                    {
                        size_t compressed_size = 0;
                        uint8_t *compressed = compress_data(
                            block_data, block_size, &compressed_size, cf->config.compress_algo);
                        if (compressed)
                        {
                            free(block_data);
                            final_data = compressed;
                            final_size = compressed_size;
                        }
                    }

                    block_manager_block_t *block =
                        block_manager_block_create(final_size, final_data);
                    if (block)
                    {
                        long offset = block_manager_block_write(sst->block_manager, block);
                        if (offset >= 0)
                        {
                            bloom_filter_add(sst->bloom_filter, k, k_size);
                            binary_hash_array_add(sst->index, k, k_size, offset);
                            sst->num_entries++;
                        }
                        block_manager_block_free(block);
                    }
                    free(final_data);
                }
            }
        }
        skip_list_cursor_free(cursor);
    }

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

    size_t index_size = 0;
    uint8_t *index_data = binary_hash_array_serialize(sst->index, &index_size);
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

    if (sst->min_key && sst->max_key)
    {
        uint32_t magic = 0x5353544D;
        size_t metadata_size = sizeof(uint32_t) + sizeof(uint64_t) + sizeof(uint32_t) +
                               sst->min_key_size + sizeof(uint32_t) + sst->max_key_size;
        uint8_t *metadata = malloc(metadata_size);
        if (metadata)
        {
            uint8_t *ptr = metadata;
            memcpy(ptr, &magic, sizeof(uint32_t));
            ptr += sizeof(uint32_t);
            uint64_t num_entries_u64 = (uint64_t)sst->num_entries;
            memcpy(ptr, &num_entries_u64, sizeof(uint64_t));
            ptr += sizeof(uint64_t);
            uint32_t min_size = (uint32_t)sst->min_key_size;
            memcpy(ptr, &min_size, sizeof(uint32_t));
            ptr += sizeof(uint32_t);
            memcpy(ptr, sst->min_key, sst->min_key_size);
            ptr += sst->min_key_size;
            uint32_t max_size = (uint32_t)sst->max_key_size;
            memcpy(ptr, &max_size, sizeof(uint32_t));
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
    pthread_rwlock_wrlock(&cf->cf_lock);

    if (cf->num_sstables >= cf->sstable_array_capacity)
    {
        int new_cap = cf->sstable_array_capacity == 0 ? 8 : cf->sstable_array_capacity * 2;
        tidesdb_sstable_t **new_ssts =
            realloc(cf->sstables, (size_t)new_cap * sizeof(tidesdb_sstable_t *));
        if (!new_ssts)
        {
            pthread_rwlock_unlock(&cf->cf_lock);
            tidesdb_sstable_free(sst);
            return -1;
        }
        cf->sstables = new_ssts;
        cf->sstable_array_capacity = new_cap;
    }

    cf->sstables[cf->num_sstables] = sst;
    atomic_fetch_add(&cf->num_sstables, 1);

    pthread_rwlock_unlock(&cf->cf_lock);

    return 0;
}

static void *tidesdb_flush_worker_thread(void *arg)
{
    tidesdb_column_family_t *cf = (tidesdb_column_family_t *)arg;

    while (!atomic_load(&cf->flush_stop))
    {
        tidesdb_memtable_t *mt = (tidesdb_memtable_t *)queue_dequeue_wait(cf->flush_queue);

        if (atomic_load(&cf->flush_stop)) break;

        if (mt)
        {
            tidesdb_flush_memtable_to_sstable(cf, mt);

            pthread_mutex_lock(&cf->flush_lock);
            queue_dequeue(cf->immutable_memtables);
            pthread_mutex_unlock(&cf->flush_lock);

            tidesdb_memtable_free(mt);

            int num_ssts = atomic_load(&cf->num_sstables);
            if (num_ssts >= 2 && num_ssts >= cf->config.max_sstables_before_compaction)
            {
                tidesdb_compact(cf);
            }
        }
    }

    return NULL;
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

    if (cf->config.compaction_threads > 0)
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
        return 0; /* nothing to compact */
    }

    /* copy sst pointers and acquire references */
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

    tidesdb_sstable_t **merged_ssts = calloc((size_t)pairs_to_merge, sizeof(tidesdb_sstable_t *));
    if (!merged_ssts)
    {
        free(sst_snapshot);
        pthread_mutex_unlock(&cf->compaction_lock);
        return -1;
    }

    for (int p = 0; p < pairs_to_merge; p++)
    {
        tidesdb_sstable_t *sst1 = sst_snapshot[p * 2];
        tidesdb_sstable_t *sst2 = sst_snapshot[p * 2 + 1];

        if (!sst1 || !sst2) continue;

        /* create new merged sstable with temp extension */
        uint64_t new_id = atomic_fetch_add(&cf->next_sstable_id, 1);
        char new_path[TDB_MAX_PATH_LENGTH];
        char temp_path[TDB_MAX_PATH_LENGTH];
        get_sstable_path(cf, new_id, new_path);
        (void)snprintf(temp_path, TDB_MAX_PATH_LENGTH, "%s%s", new_path, TDB_TEMP_EXT);

        TDB_DEBUG_LOG("Compacting sstables %llu and %llu into %llu (temp: %s)",
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
                                                         cf->config.sync_interval);
        if (!merged->block_manager)
        {
            free(merged);
            continue;
        }

        bloom_filter_new(&merged->bloom_filter, cf->config.bloom_filter_fp_rate,
                         sst1->num_entries + sst2->num_entries);
        merged->index =
            binary_hash_array_new((size_t)sst1->num_entries + (size_t)sst2->num_entries);

        /* merge entries from both sstables using cursors */
        block_manager_cursor_t *cursor1 = NULL;
        block_manager_cursor_t *cursor2 = NULL;
        block_manager_cursor_init(&cursor1, sst1->block_manager);
        block_manager_cursor_init(&cursor2, sst2->block_manager);

        if (cursor1) block_manager_cursor_goto_first(cursor1);
        if (cursor2) block_manager_cursor_goto_first(cursor2);

        int has1 = cursor1 ? block_manager_cursor_has_next(cursor1) : 0;
        int has2 = cursor2 ? block_manager_cursor_has_next(cursor2) : 0;

        /* track blocks read to avoid reading metadata blocks */
        int blocks_read1 = 0;
        int blocks_read2 = 0;

        while (has1 || has2)
        {
            block_manager_block_t *block = NULL;
            /* use cursor1 unless only cursor2 has data */
            int use1 = !(has2 && !has1);

            if (use1 && has1)
            {
                /* check if we've read all KV blocks from sst1 */
                if (blocks_read1 >= sst1->num_entries)
                {
                    has1 = 0;
                    continue;
                }
                block = block_manager_cursor_read(cursor1);
                blocks_read1++;
                block_manager_cursor_next(cursor1);
                has1 = block_manager_cursor_has_next(cursor1) && (blocks_read1 < sst1->num_entries);
            }
            else if (has2)
            {
                /* check if we've read all KV blocks from sst2 */
                if (blocks_read2 >= sst2->num_entries)
                {
                    has2 = 0;
                    continue;
                }
                block = block_manager_cursor_read(cursor2);
                blocks_read2++;
                block_manager_cursor_next(cursor2);
                has2 = block_manager_cursor_has_next(cursor2) && (blocks_read2 < sst2->num_entries);
            }

            if (block && block->data)
            {
                /* decompress if needed */
                uint8_t *data = block->data;
                size_t data_size = block->size;

                if (cf->config.compressed)
                {
                    size_t decompressed_size = 0;
                    uint8_t *decompressed = decompress_data(data, data_size, &decompressed_size,
                                                            cf->config.compress_algo);
                    if (decompressed)
                    {
                        data = decompressed;
                        data_size = decompressed_size;
                    }
                }

                /* parse key from block using new format */
                if (data_size < sizeof(tidesdb_kv_pair_header_t))
                {
                    if (data != block->data) free(data);
                    block_manager_block_free(block);
                    continue;
                }

                tidesdb_kv_pair_header_t header;
                memcpy(&header, data, sizeof(tidesdb_kv_pair_header_t));

                /* skip tombstones during compaction */
                if (header.flags & TDB_KV_FLAG_TOMBSTONE)
                {
                    if (data != block->data) free(data);
                    block_manager_block_free(block);
                    continue;
                }

                /* skip expired entries during compaction */
                if (header.ttl > 0 && time(NULL) > header.ttl)
                {
                    if (data != block->data) free(data);
                    block_manager_block_free(block);
                    continue;
                }

                uint8_t *key = data + sizeof(tidesdb_kv_pair_header_t);
                size_t k_size = header.key_size;

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

                if (cf->config.compressed)
                {
                    size_t compressed_size = 0;
                    uint8_t *compressed =
                        compress_data(data, data_size, &compressed_size, cf->config.compress_algo);
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
                        bloom_filter_add(merged->bloom_filter, key_copy, k_size);
                        binary_hash_array_add(merged->index, key_copy, k_size, offset);
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

        if (cursor1) block_manager_cursor_free(cursor1);
        if (cursor2) block_manager_cursor_free(cursor2);

        /* write metadata */
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

        size_t index_size = 0;
        uint8_t *index_data = binary_hash_array_serialize(merged->index, &index_size);
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
                                                             cf->config.sync_interval);
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

    pthread_rwlock_wrlock(&cf->cf_lock);

    for (int p = 0; p < pairs_to_merge; p++)
    {
        tidesdb_sstable_t *sst1 = sst_snapshot[p * 2];
        tidesdb_sstable_t *sst2 = sst_snapshot[p * 2 + 1];
        tidesdb_sstable_t *merged = merged_ssts[p];

        if (!merged) continue;

        /* replace in array first to prevent new readers from acquiring references */
        cf->sstables[p * 2] = merged;
        cf->sstables[p * 2 + 1] = NULL;
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

    pthread_rwlock_unlock(&cf->cf_lock);
    pthread_mutex_unlock(&cf->compaction_lock);

    /* release all snapshot references */
    for (int i = 0; i < num_ssts; i++)
    {
        if (sst_snapshot[i])
        {
            tidesdb_sstable_release(sst_snapshot[i]);
        }
    }

    free(sst_snapshot);
    free(merged_ssts);

    return 0;
}

/* parallel compaction structures */
typedef struct
{
    tidesdb_column_family_t *cf;
    tidesdb_sstable_t *sst1;
    tidesdb_sstable_t *sst2;
    tidesdb_sstable_t **result;
    sem_t *semaphore;
    int *error;
} compaction_job_t;

/* worker thread function for parallel compaction */
static void *tidesdb_compaction_worker(void *arg)
{
    compaction_job_t *job = (compaction_job_t *)arg;
    tidesdb_column_family_t *cf = job->cf;
    tidesdb_sstable_t *sst1 = job->sst1;
    tidesdb_sstable_t *sst2 = job->sst2;

    /* create new merged sstable with temp extension */
    uint64_t new_id = atomic_fetch_add(&cf->next_sstable_id, 1);
    char new_path[TDB_MAX_PATH_LENGTH];
    char temp_path[TDB_MAX_PATH_LENGTH];
    get_sstable_path(cf, new_id, new_path);
    (void)snprintf(temp_path, TDB_MAX_PATH_LENGTH, "%s%s", new_path, TDB_TEMP_EXT);

    TDB_DEBUG_LOG("[Thread] Compacting sstables %llu and %llu into %llu",
                  (unsigned long long)sst1->id, (unsigned long long)sst2->id,
                  (unsigned long long)new_id);

    tidesdb_sstable_t *merged = malloc(sizeof(tidesdb_sstable_t));
    if (!merged)
    {
        *job->error = 1;
        sem_post(job->semaphore);
        return NULL;
    }

    merged->id = new_id;
    merged->cf = cf;
    merged->min_key = NULL;
    merged->max_key = NULL;
    merged->num_entries = 0;
    atomic_store(&merged->ref_count, 1); /* initial reference */
    pthread_mutex_init(&merged->ref_lock, NULL);

    merged->block_manager =
        get_cached_block_manager(cf->db, temp_path, cf->config.sync_mode, cf->config.sync_interval);
    if (!merged->block_manager)
    {
        free(merged);
        *job->error = 1;
        sem_post(job->semaphore);
        return NULL;
    }

    bloom_filter_new(&merged->bloom_filter, cf->config.bloom_filter_fp_rate,
                     sst1->num_entries + sst2->num_entries);
    merged->index = binary_hash_array_new((size_t)sst1->num_entries + (size_t)sst2->num_entries);

    /* merge entries from both sstables */
    block_manager_cursor_t *cursor1 = NULL;
    block_manager_cursor_t *cursor2 = NULL;
    block_manager_cursor_init(&cursor1, sst1->block_manager);
    block_manager_cursor_init(&cursor2, sst2->block_manager);

    if (cursor1) block_manager_cursor_goto_first(cursor1);
    if (cursor2) block_manager_cursor_goto_first(cursor2);

    int has1 = cursor1 ? block_manager_cursor_has_next(cursor1) : 0;
    int has2 = cursor2 ? block_manager_cursor_has_next(cursor2) : 0;

    /* track blocks read to avoid reading metadata blocks */
    int blocks_read1 = 0;
    int blocks_read2 = 0;

    while (has1 || has2)
    {
        block_manager_block_t *block = NULL;
        /* use cursor1 unless only cursor2 has data */
        int use1 = !(has2 && !has1);

        if (use1 && has1)
        {
            /* check if we've read all KV blocks from sst1 */
            if (blocks_read1 >= sst1->num_entries)
            {
                has1 = 0;
                continue;
            }
            block = block_manager_cursor_read(cursor1);
            blocks_read1++;
            block_manager_cursor_next(cursor1);
            has1 = block_manager_cursor_has_next(cursor1) && (blocks_read1 < sst1->num_entries);
        }
        else if (has2)
        {
            /* check if we've read all KV blocks from sst2 */
            if (blocks_read2 >= sst2->num_entries)
            {
                has2 = 0;
                continue;
            }
            block = block_manager_cursor_read(cursor2);
            blocks_read2++;
            block_manager_cursor_next(cursor2);
            has2 = block_manager_cursor_has_next(cursor2) && (blocks_read2 < sst2->num_entries);
        }

        if (block && block->data)
        {
            uint8_t *data = block->data;
            size_t data_size = block->size;

            if (cf->config.compressed)
            {
                size_t decompressed_size = 0;
                uint8_t *decompressed =
                    decompress_data(data, data_size, &decompressed_size, cf->config.compress_algo);
                if (decompressed)
                {
                    data = decompressed;
                    data_size = decompressed_size;
                }
            }

            if (data_size >= sizeof(tidesdb_kv_pair_header_t))
            {
                tidesdb_kv_pair_header_t header;
                memcpy(&header, data, sizeof(tidesdb_kv_pair_header_t));

                /* skip tombstones and expired entries */
                if (!(header.flags & TDB_KV_FLAG_TOMBSTONE) &&
                    !(header.ttl > 0 && time(NULL) > header.ttl))
                {
                    uint8_t *key = data + sizeof(tidesdb_kv_pair_header_t);
                    size_t k_size = header.key_size;

                    /* write to merged sst */
                    uint8_t *final_data = data;
                    size_t final_size = data_size;

                    if (cf->config.compressed)
                    {
                        size_t compressed_size = 0;
                        uint8_t *compressed = compress_data(data, data_size, &compressed_size,
                                                            cf->config.compress_algo);
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
                            bloom_filter_add(merged->bloom_filter, key, k_size);
                            binary_hash_array_add(merged->index, key, k_size, offset);
                            merged->num_entries++;

                            /* update min/max keys */
                            if (!merged->min_key)
                            {
                                merged->min_key = malloc(k_size);
                                if (merged->min_key)
                                {
                                    memcpy(merged->min_key, key, k_size);
                                    merged->min_key_size = k_size;
                                }
                            }
                            if (merged->max_key) free(merged->max_key);
                            merged->max_key = malloc(k_size);
                            if (merged->max_key)
                            {
                                memcpy(merged->max_key, key, k_size);
                                merged->max_key_size = k_size;
                            }
                        }
                        block_manager_block_free(new_block);
                    }

                    if (cf->config.compressed && final_data != data)
                    {
                        free(final_data);
                    }
                }
            }

            if (cf->config.compressed && data != block->data)
            {
                free(data);
            }
            block_manager_block_free(block);
        }
    }

    if (cursor1) block_manager_cursor_free(cursor1);
    if (cursor2) block_manager_cursor_free(cursor2);

    /* write metadata */
    if (merged->min_key && merged->max_key)
    {
        uint32_t magic = 0x5353544D;
        size_t metadata_size = sizeof(uint32_t) + sizeof(uint64_t) + sizeof(uint32_t) +
                               merged->min_key_size + sizeof(uint32_t) + merged->max_key_size;
        uint8_t *metadata = malloc(metadata_size);
        if (metadata)
        {
            uint8_t *ptr = metadata;
            memcpy(ptr, &magic, sizeof(uint32_t));
            ptr += sizeof(uint32_t);
            uint64_t num_entries = (uint64_t)merged->num_entries;
            memcpy(ptr, &num_entries, sizeof(uint64_t));
            ptr += sizeof(uint64_t);
            uint32_t min_size = (uint32_t)merged->min_key_size;
            memcpy(ptr, &min_size, sizeof(uint32_t));
            ptr += sizeof(uint32_t);
            memcpy(ptr, merged->min_key, merged->min_key_size);
            ptr += merged->min_key_size;
            uint32_t max_size = (uint32_t)merged->max_key_size;
            memcpy(ptr, &max_size, sizeof(uint32_t));
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

    size_t index_size = 0;
    uint8_t *index_data = binary_hash_array_serialize(merged->index, &index_size);
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
                                                         cf->config.sync_interval);
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

    sem_post(job->semaphore);
    return NULL;
}

int tidesdb_compact_parallel(tidesdb_column_family_t *cf)
{
    if (!cf) return TDB_ERR_INVALID_ARGS;

    TDB_DEBUG_LOG("Starting parallel compaction for column family: %s (sstables: %d, threads: %d)",
                  cf->name, atomic_load(&cf->num_sstables), cf->config.compaction_threads);

    pthread_mutex_lock(&cf->compaction_lock);
    pthread_rwlock_wrlock(&cf->cf_lock);

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

    if (!jobs || !threads || !merged_sstables || !errors)
    {
        free(jobs);
        free(threads);
        free(merged_sstables);
        free(errors);
        sem_destroy(&semaphore);
        pthread_rwlock_unlock(&cf->cf_lock);
        pthread_mutex_unlock(&cf->compaction_lock);
        return -1;
    }

    /* launch worker threads for each pair */
    for (int p = 0; p < pairs_to_merge; p++)
    {
        sem_wait(&semaphore);

        jobs[p].cf = cf;
        jobs[p].sst1 = cf->sstables[p * 2];
        jobs[p].sst2 = cf->sstables[p * 2 + 1];
        jobs[p].result = &merged_sstables[p];
        jobs[p].semaphore = &semaphore;
        jobs[p].error = &errors[p];

        pthread_create(&threads[p], NULL, tidesdb_compaction_worker, &jobs[p]);
    }

    /* wait for all threads to complete */
    for (int p = 0; p < pairs_to_merge; p++)
    {
        pthread_join(threads[p], NULL);
    }

    /* clean up old ssts and update array */
    for (int p = 0; p < pairs_to_merge; p++)
    {
        if (!errors[p] && merged_sstables[p])
        {
            tidesdb_sstable_t *sst1 = cf->sstables[p * 2];
            tidesdb_sstable_t *sst2 = cf->sstables[p * 2 + 1];

            tidesdb_sstable_release(sst1);
            tidesdb_sstable_release(sst2);
        }
    }

    /* rebuild sstable array */
    tidesdb_sstable_t **new_sstables =
        malloc((size_t)(pairs_to_merge + (num_ssts % 2)) * sizeof(tidesdb_sstable_t *));
    int new_count = 0;

    for (int p = 0; p < pairs_to_merge; p++)
    {
        if (!errors[p] && merged_sstables[p])
        {
            new_sstables[new_count++] = merged_sstables[p];
        }
    }

    /* add odd sst if exists */
    if (num_ssts % 2 == 1)
    {
        new_sstables[new_count++] = cf->sstables[num_ssts - 1];
    }

    free(cf->sstables);
    cf->sstables = new_sstables;
    atomic_store(&cf->num_sstables, new_count);

    free(jobs);
    free(threads);
    free(merged_sstables);
    free(errors);
    sem_destroy(&semaphore);

    pthread_rwlock_unlock(&cf->cf_lock);
    pthread_mutex_unlock(&cf->compaction_lock);

    TDB_DEBUG_LOG("Parallel compaction complete: %d -> %d sstables", num_ssts, new_count);
    return 0;
}

static void *tidesdb_background_compaction_thread(void *arg)
{
    tidesdb_column_family_t *cf = (tidesdb_column_family_t *)arg;

    while (!atomic_load(&cf->compaction_stop))
    {
        int num_ssts = atomic_load(&cf->num_sstables);
        if (num_ssts >= 2 && num_ssts >= cf->config.max_sstables_before_compaction)
        {
            tidesdb_compact(cf);
        }

        usleep(cf->config.background_compaction_interval);
    }

    return NULL;
}

static int tidesdb_check_and_flush(tidesdb_column_family_t *cf)
{
    if (!cf) return TDB_ERR_INVALID_ARGS;
    
    tidesdb_memtable_t *active_mt = atomic_load(&cf->active_memtable);
    if (!active_mt) return TDB_ERR_INVALID_ARGS;
    
    tidesdb_memtable_acquire(active_mt);
    size_t memtable_size = (size_t)skip_list_get_size(active_mt->memtable);
    tidesdb_memtable_release(active_mt);
    
    if (memtable_size >= cf->config.memtable_flush_size)
    {
        return tidesdb_rotate_memtable(cf);
    }

    return 0;
}

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

    sst->block_manager =
        get_cached_block_manager(cf->db, path, cf->config.sync_mode, cf->config.sync_interval);
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
            /* check for magic number "SSTM" */
            uint8_t *ptr = metadata_block->data;
            uint32_t magic;
            memcpy(&magic, ptr, sizeof(uint32_t));

            if (magic == 0x5353544D) /* "SSTM" */
            {
                ptr += sizeof(uint32_t);
                uint64_t num_entries;
                memcpy(&num_entries, ptr, sizeof(uint64_t));
                ptr += sizeof(uint64_t);
                uint32_t min_key_size;
                memcpy(&min_key_size, ptr, sizeof(uint32_t));
                ptr += sizeof(uint32_t);

                sst->num_entries = (int)num_entries;
                sst->min_key = malloc(min_key_size);
                if (sst->min_key)
                {
                    memcpy(sst->min_key, ptr, min_key_size);
                    sst->min_key_size = min_key_size;
                }
                ptr += min_key_size;
                uint32_t max_key_size;
                memcpy(&max_key_size, ptr, sizeof(uint32_t));
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
            sst->index = binary_hash_array_deserialize(index_block->data);
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

static int tidesdb_sstable_get(tidesdb_sstable_t *sstable, const uint8_t *key, size_t key_size,
                               uint8_t **value, size_t *value_size)
{
    if (!sstable || !key || !value || !value_size) return -1;

    /* check bloom filter first */
    if (sstable->bloom_filter && !bloom_filter_contains(sstable->bloom_filter, key, key_size))
    {
        return -1; /* definitely not in sstable */
    }

    int64_t offset = -1;

    /* if SBHA is enabled, use it for direct lookup */
    if (sstable->cf->config.use_sbha && sstable->index)
    {
        offset = binary_hash_array_contains(sstable->index, (uint8_t *)key, key_size);
        if (offset < 0) return -1; /* not found in index */
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

                if (sstable->cf->config.compressed)
                {
                    size_t decompressed_size = 0;
                    uint8_t *decompressed = decompress_data(data, data_size, &decompressed_size,
                                                            sstable->cf->config.compress_algo);
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
                    continue;
                }

                tidesdb_kv_pair_header_t header;
                memcpy(&header, data, sizeof(tidesdb_kv_pair_header_t));

                uint8_t *ptr = data + sizeof(tidesdb_kv_pair_header_t);
                uint8_t *block_key = ptr;
                ptr += header.key_size;
                uint8_t *block_value = ptr;

                if (header.key_size == key_size && memcmp(block_key, key, key_size) == 0)
                {
                    /* check if deleted or expired */
                    int is_deleted = (header.flags & TDB_KV_FLAG_TOMBSTONE) != 0;
                    int is_expired = (header.ttl > 0 && time(NULL) > header.ttl);

                    if (is_deleted || is_expired)
                    {
                        if (data != block->data) free(data);
                        block_manager_block_free(block);
                        block_manager_cursor_free(cursor);
                        return TDB_ERR_NOT_FOUND;
                    }

                    /* copy value */
                    if (header.value_size > 0)
                    {
                        *value = malloc(header.value_size);
                        if (!*value)
                        {
                            if (data != block->data) free(data);
                            block_manager_block_free(block);
                            block_manager_cursor_free(cursor);
                            return -1;
                        }
                        memcpy(*value, block_value, header.value_size);
                    }
                    else
                    {
                        *value = NULL;
                    }
                    *value_size = header.value_size;

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

    /* read block at offset from SBHA */
    block_manager_cursor_t *cursor = NULL;
    if (block_manager_cursor_init(&cursor, sstable->block_manager) != 0) return -1;

    if (block_manager_cursor_goto(cursor, (uint64_t)offset) != 0)
    {
        block_manager_cursor_free(cursor);
        return -1;
    }

    block_manager_block_t *block = block_manager_cursor_read(cursor);
    block_manager_cursor_free(cursor);

    if (!block || !block->data)
    {
        if (block) block_manager_block_free(block);
        return -1;
    }

    /* decompress if needed */
    uint8_t *data = block->data;
    size_t data_size = block->size;

    if (sstable->cf->config.compressed)
    {
        size_t decompressed_size = 0;
        uint8_t *decompressed =
            decompress_data(data, data_size, &decompressed_size, sstable->cf->config.compress_algo);
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

    tidesdb_kv_pair_header_t header;
    memcpy(&header, data, sizeof(tidesdb_kv_pair_header_t));

    uint8_t *ptr = data + sizeof(tidesdb_kv_pair_header_t);
    uint8_t *block_key = ptr;
    ptr += header.key_size;
    uint8_t *block_value = ptr;

    /* verify key matches */
    if (header.key_size != key_size || memcmp(block_key, key, key_size) != 0)
    {
        if (data != block->data) free(data);
        block_manager_block_free(block);
        return -1;
    }

    /* check if deleted (tombstone) or expired */
    int is_deleted = (header.flags & TDB_KV_FLAG_TOMBSTONE) != 0;
    int is_expired = (header.ttl > 0 && time(NULL) > header.ttl);

    if (is_deleted || is_expired)
    {
        if (data != block->data) free(data);
        block_manager_block_free(block);
        return TDB_ERR_NOT_FOUND;
    }

    /* copy value, handle empty values */
    if (header.value_size > 0)
    {
        *value = malloc(header.value_size);
        if (!*value)
        {
            if (data != block->data) free(data);
            block_manager_block_free(block);
            return -1;
        }
        memcpy(*value, block_value, header.value_size);
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
    *value_size = header.value_size;

    if (data != block->data) free(data);
    block_manager_block_free(block);

    return 0;
}

static void tidesdb_sstable_free(tidesdb_sstable_t *sstable)
{
    if (!sstable) return;

    if (sstable->index)
    {
        binary_hash_array_free(sstable->index);
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

    if (cf->immutable_memtables)
    {
        pthread_mutex_lock(&cf->flush_lock);
        size_t queue_sz = queue_size(cf->immutable_memtables);
        for (ssize_t i = (ssize_t)queue_sz - 1; i >= 0; i--)
        {
            tidesdb_memtable_t *imt =
                (tidesdb_memtable_t *)queue_peek_at(cf->immutable_memtables, (size_t)i);
            if (imt && imt->memtable)
            {
                tidesdb_memtable_acquire(imt); 
                pthread_mutex_unlock(&cf->flush_lock); /* unlock while reading */
                
                uint8_t *mem_value = NULL;
                size_t mem_value_size = 0;
                uint8_t deleted = 0;

                int result = skip_list_get(imt->memtable, key, key_size, &mem_value,
                                           &mem_value_size, &deleted);
                tidesdb_memtable_release(imt);
                
                if (result == 0)
                {
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
                
                pthread_mutex_lock(&cf->flush_lock); /* re-lock for next iteration */
            }
        }
        pthread_mutex_unlock(&cf->flush_lock);
    }

    pthread_rwlock_rdlock(&cf->cf_lock);

    /* check sstables from newest to oldest */
    int num_ssts = atomic_load(&cf->num_sstables);
    for (int i = num_ssts - 1; i >= 0; i--)
    {
        tidesdb_sstable_t *sst = cf->sstables[i];
        if (!sst) continue;

        tidesdb_sstable_acquire(sst);
        pthread_rwlock_unlock(&cf->cf_lock);

        uint8_t *sst_value = NULL;
        size_t sst_value_size = 0;

        int result = tidesdb_sstable_get(sst, key, key_size, &sst_value, &sst_value_size);
        tidesdb_sstable_release(sst);

        if (result == 0)
        {
            *value = sst_value;
            *value_size = sst_value_size;
            return 0;
        }
        else if (result == TDB_ERR_NOT_FOUND)
        {
            return -1;
        }
        
        pthread_rwlock_rdlock(&cf->cf_lock);
    }

    pthread_rwlock_unlock(&cf->cf_lock);
    return -1;
}

int tidesdb_txn_begin(tidesdb_t *db, tidesdb_txn_t **txn)
{
    if (!db || !txn) return TDB_ERR_INVALID_ARGS;

    *txn = malloc(sizeof(tidesdb_txn_t));
    if (!*txn) return TDB_ERR_MEMORY;

    (*txn)->db = db;
    (*txn)->operations = NULL;
    (*txn)->num_ops = 0;
    (*txn)->op_capacity = 0;
    (*txn)->committed = 0;
    (*txn)->snapshot_version = 0;
    (*txn)->read_only = 0;

    return 0;
}

int tidesdb_txn_begin_read(tidesdb_t *db, tidesdb_txn_t **txn)
{
    if (!db || !txn) return TDB_ERR_INVALID_ARGS;

    *txn = malloc(sizeof(tidesdb_txn_t));
    if (!*txn) return TDB_ERR_MEMORY;

    (*txn)->db = db;
    (*txn)->operations = NULL;
    (*txn)->num_ops = 0;
    (*txn)->op_capacity = 0;
    (*txn)->committed = 0;
    (*txn)->snapshot_version = 0;
    (*txn)->read_only = 1;

    return 0;
}

int tidesdb_txn_get(tidesdb_txn_t *txn, const char *cf_name, const uint8_t *key, size_t key_size,
                    uint8_t **value, size_t *value_size)
{
    if (!txn || !cf_name || !key || !value || !value_size) return TDB_ERR_INVALID_ARGS;

    tidesdb_column_family_t *cf = tidesdb_get_column_family(txn->db, cf_name);
    if (!cf) return TDB_ERR_NOT_FOUND;

    /* check pending writes in transaction first (read your own writes) */
    if (!txn->read_only)
    {
        for (int i = txn->num_ops - 1; i >= 0; i--)
        {
            tidesdb_operation_t *op = &txn->operations[i];
            if (strcmp(op->cf_name, cf_name) == 0 && op->key_size == key_size &&
                memcmp(op->key, key, key_size) == 0)
            {
                if (op->type == TIDESDB_OP_DELETE)
                {
                    return TDB_ERR_NOT_FOUND;
                }
                else if (op->type == TIDESDB_OP_PUT)
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

    /* read from database */
    return tidesdb_txn_get_internal(txn, cf, key, key_size, value, value_size);
}

int tidesdb_txn_put(tidesdb_txn_t *txn, const char *cf_name, const uint8_t *key, size_t key_size,
                    const uint8_t *value, size_t value_size, time_t ttl)
{
    if (!txn || !cf_name || !key || !value) return TDB_ERR_INVALID_ARGS;
    if (txn->committed) return TDB_ERR_TXN_COMMITTED;
    if (txn->read_only) return TDB_ERR_READONLY;

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
    strncpy(op->cf_name, cf_name, TDB_MAX_CF_NAME_LENGTH - 1);
    op->cf_name[TDB_MAX_CF_NAME_LENGTH - 1] = '\0';

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

int tidesdb_txn_delete(tidesdb_txn_t *txn, const char *cf_name, const uint8_t *key, size_t key_size)
{
    if (!txn || !cf_name || !key) return TDB_ERR_INVALID_ARGS;
    if (txn->committed) return TDB_ERR_TXN_COMMITTED;
    if (txn->read_only) return TDB_ERR_READONLY;

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
    strncpy(op->cf_name, cf_name, TDB_MAX_CF_NAME_LENGTH - 1);
    op->cf_name[TDB_MAX_CF_NAME_LENGTH - 1] = '\0';

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
    if (txn->committed) return TDB_ERR_TXN_COMMITTED;
    if (txn->read_only)
    {
        txn->committed = 1;
        return 0; /* nothing to commit for read-only */
    }

    for (int i = 0; i < txn->num_ops; i++)
    {
        tidesdb_operation_t *op = &txn->operations[i];

        tidesdb_column_family_t *cf = tidesdb_get_column_family(txn->db, op->cf_name);
        if (!cf) return TDB_ERR_NOT_FOUND;

        if (op->type == TIDESDB_OP_PUT)
        {
            tidesdb_memtable_t *active_mt = atomic_load(&cf->active_memtable);
            if (!active_mt) return -1;
            
            tidesdb_memtable_acquire(active_mt);

            if (active_mt->wal)
            {
                tidesdb_kv_pair_header_t header = {.version = TDB_KV_FORMAT_VERSION,
                                                   .flags = 0,
                                                   .key_size = (uint32_t)op->key_size,
                                                   .value_size = (uint32_t)op->value_size,
                                                   .ttl = (int64_t)op->ttl};

                size_t wal_size = sizeof(tidesdb_kv_pair_header_t) + op->key_size + op->value_size;
                uint8_t *wal_data = malloc(wal_size);
                if (wal_data)
                {
                    uint8_t *ptr = wal_data;
                    memcpy(ptr, &header, sizeof(tidesdb_kv_pair_header_t));
                    ptr += sizeof(tidesdb_kv_pair_header_t);
                    memcpy(ptr, op->key, op->key_size);
                    ptr += op->key_size;
                    memcpy(ptr, op->value, op->value_size);

                    block_manager_block_t *block = block_manager_block_create(wal_size, wal_data);
                    if (block)
                    {
                        block_manager_block_write(active_mt->wal, block);
                        block_manager_block_free(block);
                    }
                    free(wal_data);
                }
            }

            int result = skip_list_put(active_mt->memtable, op->key, op->key_size, op->value,
                                       op->value_size, op->ttl);
            tidesdb_memtable_release(active_mt);
            
            if (result != 0)
            {
                return -1;
            }
        }
        else if (op->type == TIDESDB_OP_DELETE)
        {
            tidesdb_memtable_t *active_mt = atomic_load(&cf->active_memtable);
            if (!active_mt) return -1;
            
            tidesdb_memtable_acquire(active_mt); 

            if (active_mt->wal)
            {
                tidesdb_kv_pair_header_t header = {.version = TDB_KV_FORMAT_VERSION,
                                                   .flags = TDB_KV_FLAG_TOMBSTONE,
                                                   .key_size = (uint32_t)op->key_size,
                                                   .value_size = 0,
                                                   .ttl = 0};

                size_t wal_size = sizeof(tidesdb_kv_pair_header_t) + op->key_size;
                uint8_t *wal_data = malloc(wal_size);
                if (wal_data)
                {
                    uint8_t *ptr = wal_data;
                    memcpy(ptr, &header, sizeof(tidesdb_kv_pair_header_t));
                    ptr += sizeof(tidesdb_kv_pair_header_t);
                    memcpy(ptr, op->key, op->key_size);

                    block_manager_block_t *block = block_manager_block_create(wal_size, wal_data);
                    if (block)
                    {
                        block_manager_block_write(active_mt->wal, block);
                        block_manager_block_free(block);
                    }
                    free(wal_data);
                }
            }

            uint8_t empty_value = 0;
            skip_list_put(active_mt->memtable, op->key, op->key_size, &empty_value, 0, 0);
            skip_list_delete(active_mt->memtable, op->key, op->key_size);
            /* if delete fails, the put succeeded so we have a valid entry, continue */
            
            tidesdb_memtable_release(active_mt);
        }

        tidesdb_check_and_flush(cf);
    }

    txn->committed = 1;
    return 0;
}

int tidesdb_txn_rollback(tidesdb_txn_t *txn)
{
    if (!txn) return -1;

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

/* helper to parse a block and extract key/value */
static int parse_block(block_manager_block_t *block, tidesdb_column_family_t *cf, uint8_t **key,
                       size_t *key_size, uint8_t **value, size_t *value_size, uint8_t *deleted,
                       time_t *ttl)
{
    if (!block || !block->data) return -1;

    uint8_t *data = block->data;
    size_t data_size = block->size;

    if (cf->config.compressed)
    {
        size_t decompressed_size = 0;
        uint8_t *decompressed =
            decompress_data(data, data_size, &decompressed_size, cf->config.compress_algo);
        if (!decompressed)
        {
            return -1;
        }
        data = decompressed;
        data_size = decompressed_size;
    }

    /* parse format [header][key][value] */
    if (data_size < sizeof(tidesdb_kv_pair_header_t))
    {
        if (data != block->data) free(data);
        return -1;
    }

    tidesdb_kv_pair_header_t header;
    uint8_t *ptr = data;
    memcpy(&header, ptr, sizeof(tidesdb_kv_pair_header_t));
    ptr += sizeof(tidesdb_kv_pair_header_t);

    if (header.version != TDB_KV_FORMAT_VERSION)
    {
        if (data != block->data) free(data);
        return -1;
    }

    /* verify we have enough data for key and value */
    if (data_size < sizeof(tidesdb_kv_pair_header_t) + header.key_size + header.value_size)
    {
        if (data != block->data) free(data);
        return -1;
    }

    /* extract key */
    *key = malloc(header.key_size);
    if (!*key)
    {
        if (data != block->data) free(data);
        return -1;
    }
    memcpy(*key, ptr, header.key_size);
    *key_size = header.key_size;
    ptr += header.key_size;

    /* extract value handle empty values */
    if (header.value_size > 0)
    {
        *value = malloc(header.value_size);
        if (!*value)
        {
            free(*key);
            if (data != block->data) free(data);
            return -1;
        }
        memcpy(*value, ptr, header.value_size);
    }
    else
    {
        /* empty value, allocate minimal buffer to avoid NULL */
        *value = malloc(1);
        if (!*value)
        {
            free(*key);
            if (data != block->data) free(data);
            return -1;
        }
    }
    *value_size = header.value_size;

    /* extract metadata from header */
    *ttl = (time_t)header.ttl;
    *deleted = (header.flags & TDB_KV_FLAG_TOMBSTONE) ? 1 : 0;

    if (data != block->data) free(data);
    return 0;
}

/* helper to compare keys for merge iteration using column family's comparator */
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

int tidesdb_iter_new(tidesdb_txn_t *txn, const char *cf_name, tidesdb_iter_t **iter)
{
    if (!txn || !cf_name || !iter) return TDB_ERR_INVALID_ARGS;

    tidesdb_column_family_t *cf = tidesdb_get_column_family(txn->db, cf_name);
    if (!cf) return TDB_ERR_NOT_FOUND;
    
    /* check if CF is being dropped */
    if (atomic_load(&cf->is_dropping)) return TDB_ERR_INVALID_CF;

    *iter = malloc(sizeof(tidesdb_iter_t));
    if (!*iter) return TDB_ERR_MEMORY;

    (*iter)->txn = txn;
    (*iter)->cf = cf;
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

    /* create cursor for active memtable */
    (*iter)->memtable_cursor = NULL;
    (*iter)->immutable_memtable_cursors = NULL;
    (*iter)->immutable_memtables = NULL;
    (*iter)->num_immutable_cursors = 0;
    tidesdb_memtable_t *active_mt = atomic_load(&cf->active_memtable);
    if (active_mt && active_mt->memtable)
    {
        tidesdb_memtable_acquire(active_mt);
        (*iter)->memtable_cursor = skip_list_cursor_init(active_mt->memtable);
    }
    if (cf->immutable_memtables)
    {
        /* lock to prevent flush thread from dequeuing while we snapshot */
        pthread_mutex_lock(&cf->flush_lock);
        size_t num_immutable = queue_size(cf->immutable_memtables);
        if (num_immutable > 0)
        {
            (*iter)->immutable_memtable_cursors =
                malloc(num_immutable * sizeof(skip_list_cursor_t *));
            (*iter)->immutable_memtables = malloc(num_immutable * sizeof(tidesdb_memtable_t *));
            if (!(*iter)->immutable_memtable_cursors || !(*iter)->immutable_memtables)
            {
                if ((*iter)->immutable_memtable_cursors) free((*iter)->immutable_memtable_cursors);
                if ((*iter)->immutable_memtables) free((*iter)->immutable_memtables);
                pthread_mutex_unlock(&cf->flush_lock);
                if ((*iter)->memtable_cursor) skip_list_cursor_free((*iter)->memtable_cursor);
                tidesdb_memtable_t *active_mt = atomic_load(&cf->active_memtable);
                if (active_mt) tidesdb_memtable_release(active_mt);
                free(*iter);
                return TDB_ERR_MEMORY;
            }
            
            (*iter)->num_immutable_cursors = (int)num_immutable;
            
            /* cursors for each immutable memtable */
            for (size_t i = 0; i < num_immutable; i++)
            {
                tidesdb_memtable_t *imt =
                    (tidesdb_memtable_t *)queue_peek_at(cf->immutable_memtables, i);
                if (imt && imt->memtable)
                {
                    tidesdb_memtable_acquire(imt);
                    (*iter)->immutable_memtables[i] = imt;
                    (*iter)->immutable_memtable_cursors[i] =
                        skip_list_cursor_init(imt->memtable);
                }
                else
                {
                    (*iter)->immutable_memtables[i] = NULL;
                    (*iter)->immutable_memtable_cursors[i] = NULL;
                }
            }
        }
        pthread_mutex_unlock(&cf->flush_lock);
    }

    pthread_rwlock_rdlock(&cf->cf_lock);
    int num_ssts = atomic_load(&cf->num_sstables);
    (*iter)->num_sstable_cursors = num_ssts;
    (*iter)->sstable_cursors = NULL;
    (*iter)->sstables = NULL;
    (*iter)->sstable_blocks_read = NULL;

    if (num_ssts > 0)
    {
        (*iter)->sstable_cursors = malloc((size_t)num_ssts * sizeof(block_manager_cursor_t *));
        (*iter)->sstables = malloc((size_t)num_ssts * sizeof(tidesdb_sstable_t *));
        (*iter)->sstable_blocks_read = calloc((size_t)num_ssts, sizeof(int));
        if (!(*iter)->sstable_cursors || !(*iter)->sstables || !(*iter)->sstable_blocks_read)
        {
            if ((*iter)->memtable_cursor) skip_list_cursor_free((*iter)->memtable_cursor);
            if ((*iter)->sstable_cursors) free((*iter)->sstable_cursors);
            if ((*iter)->sstables) free((*iter)->sstables);
            if ((*iter)->sstable_blocks_read) free((*iter)->sstable_blocks_read);
            pthread_rwlock_unlock(&cf->cf_lock);
            free(*iter);
            return TDB_ERR_MEMORY;
        }

        for (int i = 0; i < num_ssts; i++)
        {
            (*iter)->sstable_cursors[i] = NULL;
            (*iter)->sstables[i] = cf->sstables[i];
            (*iter)->sstable_blocks_read[i] = 0;
            if (cf->sstables[i] && cf->sstables[i]->block_manager)
            {
                tidesdb_sstable_acquire(cf->sstables[i]); /* acquire reference */
                block_manager_cursor_init(&(*iter)->sstable_cursors[i],
                                          cf->sstables[i]->block_manager);
            }
        }
    }
    pthread_rwlock_unlock(&cf->cf_lock);

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

    /* populate heap with first entry from each source */
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
            if (sst && sst->num_entries > 0)
            {
                block_manager_cursor_goto(iter->sstable_cursors[i], (uint64_t)(sst->num_entries));
                iter->sstable_blocks_read[i] = sst->num_entries;
            }
            else
            {
                block_manager_cursor_goto_last(iter->sstable_cursors[i]);
            }
        }
    }

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
        if (cmp != 0) break; /* different key, stop */

        /* same key, pop and discard, refill from that source */
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

    /* refill heap from the source that produced this entry */
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

    /* skip duplicate keys from other sources (keep newest version) */
    while (iter->heap_size > 0)
    {
        int cmp = compare_keys_with_cf(iter->cf, iter->heap[0].key, iter->heap[0].key_size,
                                       entry.key, entry.key_size);
        if (cmp != 0) break; /* different key, stop */

        /* same key, pop and discard, refill from that source */
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

    /* release reference on active memtable */
    if (iter->memtable_cursor)
    {
        tidesdb_memtable_t *active_mt = atomic_load(&iter->cf->active_memtable);
        if (active_mt)
        {
            tidesdb_memtable_release(active_mt);
        }
        skip_list_cursor_free(iter->memtable_cursor);
    }

    /* release references on immutable memtables */
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

    /* release references on sstables */
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