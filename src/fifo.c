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
#include "fifo.h"

#include <sched.h>

#include "xxhash.h"

/*
 * lock-free fifo cache implementation
 *
 * this combines several lock-free techniques:
 * 1. harris-style logical deletion with mark bits for hash chains
 * 2. michael-scott queue algorithm for fifo eviction order
 * 3. atomic state machine for safe entry lifecycle
 *
 * memory reclamation uses a simplified approach with deferred freeing.
 * for production use, consider implementing hazard pointers or epoch-based
 * reclamation for stronger guarantees.
 */

/* configuration */
#define FIFO_MAX_RETRIES   1000
#define FIFO_BACKOFF_LIMIT 64
#define FIFO_RETIRED_BATCH 64

/*
 * fifo_hash
 * hash function for string keys using xxhash
 * @param key the key to hash
 * @param len the length of the key
 * @return the hash value
 */
static inline uint64_t fifo_hash(const char *key, size_t len)
{
    return XXH64(key, len, 0);
}

/* tagged pointer helpers */

/*
 * make_tagged_ptr
 * create a tagged pointer combining a raw pointer and version tag
 * @param ptr the raw pointer
 * @param tag the version counter
 * @param marked whether the pointer is logically deleted
 * @return tagged pointer value
 */
static inline fifo_tagged_ptr_t make_tagged_ptr(fifo_entry_t *ptr, uintptr_t tag, int marked)
{
    fifo_tagged_ptr_t tp;
    uintptr_t p = (uintptr_t)ptr & FIFO_PTR_MASK;
    uintptr_t t = (tag << (sizeof(uintptr_t) * 8 - FIFO_TAG_BITS)) & FIFO_TAG_MASK;
    uintptr_t m = marked ? FIFO_MARK_BIT : 0;
    tp.value = p | t | m;
    return tp;
}

/*
 * get_ptr
 * extract the raw pointer from a tagged pointer
 * @param tp the tagged pointer
 * @return raw pointer to fifo_entry_t
 */
static inline fifo_entry_t *get_ptr(fifo_tagged_ptr_t tp)
{
    return (fifo_entry_t *)(tp.value & FIFO_PTR_MASK);
}

/*
 * get_tag
 * extract the version tag from a tagged pointer
 * @param tp the tagged pointer
 * @return version counter
 */
static inline uintptr_t get_tag(fifo_tagged_ptr_t tp)
{
    return (tp.value & FIFO_TAG_MASK) >> (sizeof(uintptr_t) * 8 - FIFO_TAG_BITS);
}

/*
 * is_marked
 * check if pointer is logically deleted
 * @param tp the tagged pointer
 * @return 1 if marked, 0 otherwise
 */
static inline int is_marked(fifo_tagged_ptr_t tp)
{
    return (tp.value & FIFO_MARK_BIT) != 0;
}

/*
 * set_mark
 * set the logical deletion mark on a tagged pointer
 * @param tp the tagged pointer
 * @return tagged pointer with mark bit set
 */
static inline fifo_tagged_ptr_t set_mark(fifo_tagged_ptr_t tp)
{
    fifo_tagged_ptr_t result;
    result.value = tp.value | FIFO_MARK_BIT;
    return result;
}

/*
 * tagged_ptr_equals
 * compare two tagged pointers for equality
 * @param a first tagged pointer
 * @param b second tagged pointer
 * @return 1 if equal, 0 otherwise
 */
static inline int tagged_ptr_equals(fifo_tagged_ptr_t a, fifo_tagged_ptr_t b)
{
    return a.value == b.value;
}

/* backoff and utility */

static inline void backoff(int iteration)
{
    if (iteration < 10)
    {
        cpu_pause();
    }
    else if (iteration < FIFO_BACKOFF_LIMIT)
    {
        for (int i = 0; i < iteration; i++) cpu_pause();
    }
    else
    {
        sched_yield();
    }
}

/* entry allocation and state management */

/*
 * fifo_entry_new
 * allocate and initialize a new entry
 * @param key the key string
 * @param key_len length of key
 * @param key_hash precomputed hash
 * @param value the value pointer
 * @param evict_cb eviction callback
 * @param user_data user data for callback
 * @return new entry or NULL on failure
 */
static fifo_entry_t *fifo_entry_new(const char *key, size_t key_len, uint64_t key_hash, void *value,
                                    fifo_evict_callback_t evict_cb, void *user_data)
{
    fifo_entry_t *entry = (fifo_entry_t *)malloc(sizeof(fifo_entry_t));
    if (!entry) return NULL;

    entry->key = (char *)malloc(key_len + 1);
    if (!entry->key)
    {
        free(entry);
        return NULL;
    }

    memcpy(entry->key, key, key_len);
    entry->key[key_len] = '\0';
    entry->key_len = key_len;
    entry->key_hash = key_hash;

    atomic_store(&entry->state, ENTRY_STATE_INSERTING);
    atomic_store(&entry->value, value);
    entry->evict_cb = evict_cb;
    entry->user_data = user_data;
    atomic_store(&entry->hash_next, make_tagged_ptr(NULL, 0, 0));
    atomic_store(&entry->seq_num, 0);

    return entry;
}

/*
 * fifo_entry_free
 * free an entry and optionally call its callback
 * @param entry the entry to free
 * @param call_callback whether to call eviction callback
 */
static void fifo_entry_free(fifo_entry_t *entry, int call_callback)
{
    if (!entry) return;

    if (call_callback && entry->evict_cb)
    {
        /* Only call callback if entry wasn't already evicted (state != DELETED) */
        int state = atomic_load(&entry->state);
        if (state != ENTRY_STATE_DELETED)
        {
            void *val = atomic_load(&entry->value);
            entry->evict_cb(entry->key, val, entry->user_data);
        }
    }

    free(entry->key);
    free(entry);
}

/*
 * entry_cas_state
 * try to transition entry state atomically
 * @param entry the entry
 * @param expected expected current state
 * @param desired desired new state
 * @return 1 if successful, 0 otherwise
 */
static inline int entry_cas_state(fifo_entry_t *entry, int expected, int desired)
{
    return atomic_compare_exchange_strong(&entry->state, &expected, desired);
}

/* deferred reclamation */

/*
 * fifo_retire_entry
 * add entry to retired list for deferred freeing
 * @param cache the cache
 * @param entry the entry to retire
 */
static void fifo_retire_entry(fifo_cache_t *cache, fifo_entry_t *entry)
{
    pthread_mutex_lock(&cache->retired_lock);

    size_t count = atomic_load(&cache->retired_count);

    /* if list is full, free everything */
    if (count >= cache->retired_capacity)
    {
        for (size_t i = 0; i < count; i++)
        {
            fifo_entry_free(cache->retired_list[i], 0);
        }
        count = 0;
        atomic_store(&cache->retired_count, 0);
    }

    /* add to retired list */
    if (count < cache->retired_capacity)
    {
        cache->retired_list[count] = entry;
        atomic_store(&cache->retired_count, count + 1);
    }
    else
    {
        fifo_entry_free(entry, 0);
    }

    pthread_mutex_unlock(&cache->retired_lock);
}

/* fifo eviction queue (michael-scott style) */

/*
 * fifo_order_node_new
 * allocate a new order node
 * @param entry the entry this node tracks
 * @return new node or NULL on failure
 */
static fifo_order_node_t *fifo_order_node_new(fifo_entry_t *entry)
{
    fifo_order_node_t *node = (fifo_order_node_t *)malloc(sizeof(fifo_order_node_t));
    if (!node) return NULL;

    node->entry = entry;
    atomic_store(&node->next, NULL);
    return node;
}

/*
 * fifo_enqueue_order
 * add entry to eviction queue (lock-free)
 * @param cache the cache
 * @param entry the entry to enqueue
 * @return 0 on success, -1 on failure
 */
static int fifo_enqueue_order(fifo_cache_t *cache, fifo_entry_t *entry)
{
    fifo_order_node_t *node = fifo_order_node_new(entry);
    if (!node) return -1;

    int retries = 0;
    while (retries < FIFO_MAX_RETRIES)
    {
        fifo_order_node_t *tail = atomic_load(&cache->evict_tail);
        fifo_order_node_t *next = atomic_load(&tail->next);

        if (tail == atomic_load(&cache->evict_tail))
        {
            if (next == NULL)
            {
                /* try to link node at end */
                if (atomic_compare_exchange_strong(&tail->next, &next, node))
                {
                    /* try to swing tail (ok if fails, another thread will do it) */
                    atomic_compare_exchange_strong(&cache->evict_tail, &tail, node);
                    return 0;
                }
            }
            else
            {
                /* tail is behind, try to advance */
                atomic_compare_exchange_strong(&cache->evict_tail, &tail, next);
            }
        }

        backoff(retries++);
    }

    free(node);
    return -1;
}

/*
 * fifo_dequeue_order
 * remove oldest entry from eviction queue (lock-free)
 * @param cache the cache
 * @return the oldest entry, or NULL if empty
 */
static fifo_entry_t *fifo_dequeue_order(fifo_cache_t *cache)
{
    int retries = 0;
    while (retries < FIFO_MAX_RETRIES)
    {
        fifo_order_node_t *head = atomic_load(&cache->evict_head);
        fifo_order_node_t *tail = atomic_load(&cache->evict_tail);
        fifo_order_node_t *next = atomic_load(&head->next);

        if (head == atomic_load(&cache->evict_head))
        {
            if (head == tail)
            {
                if (next == NULL)
                {
                    /* queue is empty */
                    return NULL;
                }
                /* tail is behind, advance it */
                atomic_compare_exchange_strong(&cache->evict_tail, &tail, next);
            }
            else
            {
                /* read entry before cas */
                fifo_entry_t *entry = next->entry;

                /* try to swing head to next */
                if (atomic_compare_exchange_strong(&cache->evict_head, &head, next))
                {
                    /* successfully dequeued, free old sentinel */
                    free(head);
                    return entry;
                }
            }
        }

        backoff(retries++);
    }

    return NULL;
}

/* hash table operations (harris-style with logical deletion) */

/*
 * fifo_find
 * search for key in hash chain, physically removing marked nodes
 * @param cache the cache
 * @param key the key to find
 * @param key_len length of key
 * @param key_hash precomputed hash
 * @param pred_ptr output: pointer to predecessor's next field
 * @param pred_tagged output: predecessor's tagged pointer value
 * @return entry if found and active, NULL otherwise
 */
static fifo_entry_t *fifo_find(fifo_cache_t *cache, const char *key, size_t key_len,
                               uint64_t key_hash, _Atomic(fifo_tagged_ptr_t) **pred_ptr,
                               fifo_tagged_ptr_t *pred_tagged)
{
    size_t bucket = key_hash % cache->table_size;

retry:
    *pred_ptr = &cache->table[bucket];
    *pred_tagged = atomic_load(*pred_ptr);
    fifo_entry_t *curr = get_ptr(*pred_tagged);

    while (curr != NULL)
    {
        fifo_tagged_ptr_t curr_next = atomic_load(&curr->hash_next);
        fifo_entry_t *next = get_ptr(curr_next);

        if (is_marked(curr_next))
        {
            /* node is logically deleted, try to physically remove */
            fifo_tagged_ptr_t new_ptr = make_tagged_ptr(next, get_tag(*pred_tagged) + 1, 0);
            if (!atomic_compare_exchange_strong(*pred_ptr, pred_tagged, new_ptr))
            {
                goto retry;
            }

            /* successfully unlinked, retire the node */
            fifo_retire_entry(cache, curr);
            curr = next;
        }
        else
        {
            /* check if this is our key */
            if (curr->key_hash == key_hash && curr->key_len == key_len &&
                memcmp(curr->key, key, key_len) == 0)
            {
                int state = atomic_load(&curr->state);
                if (state == ENTRY_STATE_ACTIVE || state == ENTRY_STATE_UPDATING)
                {
                    return curr;
                }
                /* entry exists but not active */
                return NULL;
            }

            /* move to next */
            *pred_ptr = &curr->hash_next;
            *pred_tagged = curr_next;
            curr = next;
        }
    }

    return NULL;
}

/*
 * fifo_insert_hash
 * insert entry into hash chain
 * @param cache the cache
 * @param entry the entry to insert
 * @return 0 on success, -1 on failure
 */
static int fifo_insert_hash(fifo_cache_t *cache, fifo_entry_t *entry)
{
    size_t bucket = entry->key_hash % cache->table_size;
    int retries = 0;

    while (retries < FIFO_MAX_RETRIES)
    {
        fifo_tagged_ptr_t head = atomic_load(&cache->table[bucket]);
        fifo_entry_t *head_ptr = get_ptr(head);

        /* set entry's next to current head */
        atomic_store(&entry->hash_next, make_tagged_ptr(head_ptr, 0, 0));

        /* try to cas head to point to new entry */
        fifo_tagged_ptr_t new_head = make_tagged_ptr(entry, get_tag(head) + 1, 0);
        if (atomic_compare_exchange_strong(&cache->table[bucket], &head, new_head))
        {
            return 0;
        }

        backoff(retries++);
    }

    return -1;
}

/*
 * fifo_mark_deleted
 * logically delete entry by setting mark bit
 * @param entry the entry to mark
 * @return 0 on success, -1 on failure
 */
static int fifo_mark_deleted(fifo_entry_t *entry)
{
    int retries = 0;
    while (retries < FIFO_MAX_RETRIES)
    {
        fifo_tagged_ptr_t curr_next = atomic_load(&entry->hash_next);
        if (is_marked(curr_next))
        {
            /* already marked */
            return 0;
        }

        fifo_tagged_ptr_t marked = set_mark(curr_next);
        if (atomic_compare_exchange_strong(&entry->hash_next, &curr_next, marked))
        {
            return 0;
        }

        backoff(retries++);
    }
    return -1;
}

/* eviction */

/*
 * fifo_try_evict_one
 * attempt to evict the oldest entry
 * @param cache the cache
 * @return 0 on success, -1 on failure
 */
static int fifo_try_evict_one(fifo_cache_t *cache)
{
    int attempts = 0;
    while (attempts < FIFO_MAX_RETRIES)
    {
        fifo_entry_t *victim = fifo_dequeue_order(cache);
        if (!victim)
        {
            /* no entries to evict */
            return -1;
        }

        /* try to transition to evicting state */
        int state = ENTRY_STATE_ACTIVE;
        if (atomic_compare_exchange_strong(&victim->state, &state, ENTRY_STATE_EVICTING))
        {
            /* successfully claimed for eviction */

            /* call eviction callback */
            if (victim->evict_cb)
            {
                void *val = atomic_load(&victim->value);
                victim->evict_cb(victim->key, val, victim->user_data);
            }

            /* mark as deleted in hash table */
            fifo_mark_deleted(victim);

            /* transition to deleted state */
            atomic_store(&victim->state, ENTRY_STATE_DELETED);

            /* decrement size */
            atomic_fetch_sub(&cache->size, 1);

            return 0;
        }

        /* entry was already being modified, try next */
        attempts++;
    }

    return -1;
}

/* public api */

fifo_cache_t *fifo_cache_new(size_t capacity)
{
    if (capacity == 0) return NULL;

    fifo_cache_t *cache = (fifo_cache_t *)calloc(1, sizeof(fifo_cache_t));
    if (!cache) return NULL;

    cache->capacity = capacity;
    atomic_store(&cache->size, 0);

    /* hash table with ~2x capacity for good load factor */
    cache->table_size = capacity * 2;
    if (cache->table_size < 16) cache->table_size = 16;

    cache->table =
        (_Atomic(fifo_tagged_ptr_t) *)calloc(cache->table_size, sizeof(_Atomic(fifo_tagged_ptr_t)));
    if (!cache->table)
    {
        free(cache);
        return NULL;
    }

    /* initialize all buckets to null */
    for (size_t i = 0; i < cache->table_size; i++)
    {
        atomic_store(&cache->table[i], make_tagged_ptr(NULL, 0, 0));
    }

    /* create sentinel node for eviction queue */
    fifo_order_node_t *sentinel = fifo_order_node_new(NULL);
    if (!sentinel)
    {
        free(cache->table);
        free(cache);
        return NULL;
    }
    atomic_store(&cache->evict_head, sentinel);
    atomic_store(&cache->evict_tail, sentinel);

    atomic_store(&cache->seq_counter, 0);

    /* retired list for deferred reclamation */
    cache->retired_capacity = FIFO_RETIRED_BATCH;
    cache->retired_list = (fifo_entry_t **)calloc(cache->retired_capacity, sizeof(fifo_entry_t *));
    if (!cache->retired_list)
    {
        free(sentinel);
        free(cache->table);
        free(cache);
        return NULL;
    }
    atomic_store(&cache->retired_count, 0);

    if (pthread_mutex_init(&cache->retired_lock, NULL) != 0)
    {
        free(cache->retired_list);
        free(sentinel);
        free(cache->table);
        free(cache);
        return NULL;
    }

    return cache;
}

int fifo_cache_put(fifo_cache_t *cache, const char *key, void *value,
                   fifo_evict_callback_t evict_cb, void *user_data)
{
    if (!cache || !key) return -1;

    size_t key_len = strlen(key);
    uint64_t key_hash = fifo_hash(key, key_len);

    int retries = 0;
    while (retries < FIFO_MAX_RETRIES)
    {
        /* check if entry already exists */
        _Atomic(fifo_tagged_ptr_t) *pred_ptr;
        fifo_tagged_ptr_t pred_tagged;
        fifo_entry_t *existing = fifo_find(cache, key, key_len, key_hash, &pred_ptr, &pred_tagged);

        if (existing)
        {
            /* try to update existing entry */
            int state = ENTRY_STATE_ACTIVE;
            if (atomic_compare_exchange_strong(&existing->state, &state, ENTRY_STATE_UPDATING))
            {
                /* call callback on old value */
                if (existing->evict_cb)
                {
                    void *old_val = atomic_load(&existing->value);
                    existing->evict_cb(existing->key, old_val, existing->user_data);
                }

                /* update value and callback */
                atomic_store(&existing->value, value);
                existing->evict_cb = evict_cb;
                existing->user_data = user_data;

                /* transition back to active */
                atomic_store(&existing->state, ENTRY_STATE_ACTIVE);
                return 0;
            }
            /* state changed, retry */
            backoff(retries++);
            continue;
        }

        /* need to insert new entry */

        /* reserve our slot first by incrementing size */
        size_t new_size = atomic_fetch_add(&cache->size, 1) + 1;

        /* if over capacity, evict entries until we have room */
        while (new_size > cache->capacity)
        {
            if (fifo_try_evict_one(cache) == 0)
            {
                new_size = atomic_load(&cache->size);
            }
            else
            {
                /* couldn't evict, someone else might be evicting */
                sched_yield();
                new_size = atomic_load(&cache->size);
            }
        }

        /* create new entry */
        fifo_entry_t *entry = fifo_entry_new(key, key_len, key_hash, value, evict_cb, user_data);
        if (!entry)
        {
            atomic_fetch_sub(&cache->size, 1); /* release reserved slot */
            return -1;
        }

        /* assign sequence number */
        uint64_t seq = atomic_fetch_add(&cache->seq_counter, 1);
        atomic_store(&entry->seq_num, seq);

        /* insert into hash table */
        if (fifo_insert_hash(cache, entry) != 0)
        {
            fifo_entry_free(entry, 0);
            atomic_fetch_sub(&cache->size, 1); /* release reserved slot */
            backoff(retries++);
            continue;
        }

        /* transition to active */
        atomic_store(&entry->state, ENTRY_STATE_ACTIVE);

        /* add to eviction queue */
        if (fifo_enqueue_order(cache, entry) != 0)
        {
            fifo_mark_deleted(entry);
            atomic_store(&entry->state, ENTRY_STATE_DELETED);
            atomic_fetch_sub(&cache->size, 1); /* release our reserved slot */
            backoff(retries++);
            continue;
        }

        /* success! size was already incremented */
        return 0;
    }

    return -1;
}

void *fifo_cache_get(fifo_cache_t *cache, const char *key)
{
    if (!cache || !key) return NULL;

    size_t key_len = strlen(key);
    uint64_t key_hash = fifo_hash(key, key_len);

    _Atomic(fifo_tagged_ptr_t) *pred_ptr;
    fifo_tagged_ptr_t pred_tagged;
    fifo_entry_t *entry = fifo_find(cache, key, key_len, key_hash, &pred_ptr, &pred_tagged);

    if (entry)
    {
        int state = atomic_load(&entry->state);
        if (state == ENTRY_STATE_ACTIVE || state == ENTRY_STATE_UPDATING)
        {
            return atomic_load(&entry->value);
        }
    }

    return NULL;
}

int fifo_cache_remove(fifo_cache_t *cache, const char *key)
{
    if (!cache || !key) return -1;

    size_t key_len = strlen(key);
    uint64_t key_hash = fifo_hash(key, key_len);

    int retries = 0;
    while (retries < FIFO_MAX_RETRIES)
    {
        _Atomic(fifo_tagged_ptr_t) *pred_ptr;
        fifo_tagged_ptr_t pred_tagged;
        fifo_entry_t *entry = fifo_find(cache, key, key_len, key_hash, &pred_ptr, &pred_tagged);

        if (!entry) return -1;

        /* try to transition to evicting */
        int state = ENTRY_STATE_ACTIVE;
        if (atomic_compare_exchange_strong(&entry->state, &state, ENTRY_STATE_EVICTING))
        {
            /* call eviction callback */
            if (entry->evict_cb)
            {
                void *val = atomic_load(&entry->value);
                entry->evict_cb(entry->key, val, entry->user_data);
            }

            /* mark as deleted */
            fifo_mark_deleted(entry);
            atomic_store(&entry->state, ENTRY_STATE_DELETED);

            atomic_fetch_sub(&cache->size, 1);
            return 0;
        }

        backoff(retries++);
    }

    return -1;
}

void fifo_cache_clear(fifo_cache_t *cache)
{
    if (!cache) return;

    /* clear by evicting all entries */
    while (atomic_load(&cache->size) > 0)
    {
        if (fifo_try_evict_one(cache) != 0)
        {
            /* no more entries or eviction failed */
            break;
        }
    }
}

void fifo_cache_free(fifo_cache_t *cache)
{
    if (!cache) return;

    /* clear all entries (calls callbacks) */
    fifo_cache_clear(cache);

    /* free remaining entries in hash table, calling callbacks to ensure proper cleanup */
    for (size_t i = 0; i < cache->table_size; i++)
    {
        fifo_tagged_ptr_t tp = atomic_load(&cache->table[i]);
        fifo_entry_t *entry = get_ptr(tp);
        while (entry)
        {
            fifo_tagged_ptr_t next_tp = atomic_load(&entry->hash_next);
            fifo_entry_t *next = get_ptr(next_tp);
            fifo_entry_free(entry, 1); /* call callback to unref SSTables/blocks */
            entry = next;
        }
    }

    /* free eviction queue */
    fifo_order_node_t *node = atomic_load(&cache->evict_head);
    while (node)
    {
        fifo_order_node_t *next = atomic_load(&node->next);
        free(node);
        node = next;
    }

    /* free retired list, calling callbacks to ensure proper cleanup */
    pthread_mutex_lock(&cache->retired_lock);
    size_t retired_count = atomic_load(&cache->retired_count);
    for (size_t i = 0; i < retired_count; i++)
    {
        fifo_entry_free(cache->retired_list[i], 1); /* call callback to unref SSTables/blocks */
    }
    pthread_mutex_unlock(&cache->retired_lock);
    pthread_mutex_destroy(&cache->retired_lock);
    free(cache->retired_list);

    free(cache->table);
    free(cache);
}

void fifo_cache_destroy(fifo_cache_t *cache)
{
    if (!cache) return;

    /* free entries without callbacks */
    for (size_t i = 0; i < cache->table_size; i++)
    {
        fifo_tagged_ptr_t tp = atomic_load(&cache->table[i]);
        fifo_entry_t *entry = get_ptr(tp);
        while (entry)
        {
            fifo_tagged_ptr_t next_tp = atomic_load(&entry->hash_next);
            fifo_entry_t *next = get_ptr(next_tp);
            free(entry->key);
            free(entry);
            entry = next;
        }
    }

    /* free eviction queue */
    fifo_order_node_t *node = atomic_load(&cache->evict_head);
    while (node)
    {
        fifo_order_node_t *next = atomic_load(&node->next);
        free(node);
        node = next;
    }

    /* free retired list */
    pthread_mutex_lock(&cache->retired_lock);
    size_t retired_count = atomic_load(&cache->retired_count);
    for (size_t i = 0; i < retired_count; i++)
    {
        free(cache->retired_list[i]->key);
        free(cache->retired_list[i]);
    }
    pthread_mutex_unlock(&cache->retired_lock);
    pthread_mutex_destroy(&cache->retired_lock);
    free(cache->retired_list);

    free(cache->table);
    free(cache);
}

size_t fifo_cache_size(fifo_cache_t *cache)
{
    if (!cache) return 0;
    return atomic_load(&cache->size);
}

size_t fifo_cache_capacity(fifo_cache_t *cache)
{
    if (!cache) return 0;
    return cache->capacity;
}

size_t fifo_cache_foreach(fifo_cache_t *cache, fifo_foreach_callback_t callback, void *user_data)
{
    if (!cache || !callback) return 0;

    size_t count = 0;

    for (size_t i = 0; i < cache->table_size; i++)
    {
        fifo_tagged_ptr_t tp = atomic_load(&cache->table[i]);
        fifo_entry_t *entry = get_ptr(tp);

        while (entry)
        {
            fifo_tagged_ptr_t next_tp = atomic_load(&entry->hash_next);

            if (!is_marked(next_tp))
            {
                int state = atomic_load(&entry->state);
                if (state == ENTRY_STATE_ACTIVE)
                {
                    void *val = atomic_load(&entry->value);
                    int result = callback(entry->key, val, user_data);
                    count++;

                    if (result != 0) return count;
                }
            }

            entry = get_ptr(next_tp);
        }
    }

    return count;
}