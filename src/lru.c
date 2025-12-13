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

#include "lru.h"

#include "xxhash.h"

typedef struct cache_entry_t
{
    char *key;
    void *value;
    uint32_t access_count;
    time_t expiry_time;
    lru_evict_callback_t evict_cb;
    void *user_data;
    struct cache_entry_t *prev;
    struct cache_entry_t *next;
} cache_entry_t;

typedef struct
{
    cache_entry_t **entries;
    size_t count;
    size_t capacity;
} hash_bucket_t;

typedef struct
{
    hash_bucket_t *buckets;
    size_t num_buckets;
} hash_table_t;

struct lru_cache_t
{
    cache_entry_t *lru_head;
    cache_entry_t *lru_tail;
    size_t lru_size;
    size_t lru_capacity;
    cache_entry_t *lfu_head;
    cache_entry_t *lfu_tail;
    size_t lfu_size;
    size_t lfu_capacity;
    hash_table_t *hash_table;
    uint32_t promotion_threshold;
    uint32_t ttl_seconds;
    uint64_t hits;
    uint64_t misses;
    pthread_rwlock_t lock;
};

static void entry_free(cache_entry_t *entry, int call_callback);
static cache_entry_t *entry_create(const char *key, void *value, lru_evict_callback_t evict_cb,
                                   void *user_data);
static void list_remove(cache_entry_t **head, cache_entry_t **tail, cache_entry_t *entry);
static void list_push_front(cache_entry_t **head, cache_entry_t **tail, cache_entry_t *entry);
static hash_table_t *hash_table_create(size_t num_buckets);
static void hash_table_destroy(hash_table_t *ht);
static cache_entry_t *hash_table_find(hash_table_t *ht, const char *key);
static cache_entry_t *hash_table_find_n(hash_table_t *ht, const char *key, size_t key_len);
static int hash_table_insert(hash_table_t *ht, cache_entry_t *entry);
static void hash_table_remove(hash_table_t *ht, const char *key);
static void evict_lru_entry(lru_cache_t *cache);
static void evict_lfu_entry(lru_cache_t *cache);
static void promote_to_lfu(lru_cache_t *cache, cache_entry_t *entry);
static void expire_lfu_entries(lru_cache_t *cache);

lru_cache_t *lru_cache_new(size_t lru_capacity, size_t lfu_capacity, uint32_t promotion_threshold,
                           uint32_t ttl_seconds)
{
    if (lru_capacity == 0) return NULL;

    lru_cache_t *cache = (lru_cache_t *)calloc(1, sizeof(lru_cache_t));
    if (!cache) return NULL;

    cache->lru_capacity = lru_capacity;
    cache->lfu_capacity = lfu_capacity;
    cache->promotion_threshold = promotion_threshold;
    cache->ttl_seconds = ttl_seconds;

    size_t num_buckets = (lru_capacity + lfu_capacity) / 4;
    if (num_buckets < 16) num_buckets = 16;
    cache->hash_table = hash_table_create(num_buckets);
    if (!cache->hash_table)
    {
        free(cache);
        return NULL;
    }

    if (pthread_rwlock_init(&cache->lock, NULL) != 0)
    {
        hash_table_destroy(cache->hash_table);
        free(cache);
        return NULL;
    }

    return cache;
}

int lru_cache_put(lru_cache_t *cache, const char *key, void *value, lru_evict_callback_t evict_cb,
                  void *user_data)
{
    if (!cache || !key) return -1;

    pthread_rwlock_wrlock(&cache->lock);

    cache_entry_t *existing = hash_table_find(cache->hash_table, key);
    if (existing)
    {
        void *old_value = existing->value;
        existing->value = value;

        if (existing->evict_cb && old_value)
        {
            existing->evict_cb(existing->key, old_value, existing->user_data);
        }

        existing->evict_cb = evict_cb;
        existing->user_data = user_data;

        existing->access_count = 1;

        int in_lru = 0;
        cache_entry_t *check = cache->lru_head;
        while (check)
        {
            if (check == existing)
            {
                in_lru = 1;
                break;
            }
            check = check->next;
        }

        if (in_lru)
        {
            list_remove(&cache->lru_head, &cache->lru_tail, existing);
            list_push_front(&cache->lru_head, &cache->lru_tail, existing);
        }
        else
        {
            list_remove(&cache->lfu_head, &cache->lfu_tail, existing);
            list_push_front(&cache->lfu_head, &cache->lfu_tail, existing);
            if (cache->ttl_seconds > 0)
            {
                existing->expiry_time = time(NULL) + cache->ttl_seconds;
            }
        }

        pthread_rwlock_unlock(&cache->lock);
        return 1; /* return 1 for update */
    }

    cache_entry_t *entry = entry_create(key, value, evict_cb, user_data);
    if (!entry)
    {
        pthread_rwlock_unlock(&cache->lock);
        return -1;
    }

    if (cache->lru_size >= cache->lru_capacity)
    {
        evict_lru_entry(cache);
    }

    list_push_front(&cache->lru_head, &cache->lru_tail, entry);
    cache->lru_size++;

    if (hash_table_insert(cache->hash_table, entry) != 0)
    {
        list_remove(&cache->lru_head, &cache->lru_tail, entry);
        cache->lru_size--;
        entry_free(entry, 0);
        pthread_rwlock_unlock(&cache->lock);
        return -1;
    }

    pthread_rwlock_unlock(&cache->lock);
    return 0;
}

void *lru_cache_get(lru_cache_t *cache, const char *key)
{
    if (!cache || !key) return NULL;

    pthread_rwlock_wrlock(&cache->lock);

    if (cache->ttl_seconds > 0)
    {
        expire_lfu_entries(cache);
    }

    cache_entry_t *entry = hash_table_find(cache->hash_table, key);
    if (!entry)
    {
        cache->misses++;
        pthread_rwlock_unlock(&cache->lock);
        return NULL;
    }

    cache->hits++;

    entry->access_count++;

    if (entry->access_count >= cache->promotion_threshold && cache->lfu_capacity > 0)
    {
        cache_entry_t *check = cache->lru_head;
        while (check)
        {
            if (check == entry)
            {
                promote_to_lfu(cache, entry);
                break;
            }
            check = check->next;
        }
    }
    else
    {
        int in_lru = 0;
        cache_entry_t *check = cache->lru_head;
        while (check)
        {
            if (check == entry)
            {
                in_lru = 1;
                break;
            }
            check = check->next;
        }

        if (in_lru)
        {
            list_remove(&cache->lru_head, &cache->lru_tail, entry);
            list_push_front(&cache->lru_head, &cache->lru_tail, entry);
        }
        else
        {
            if (cache->ttl_seconds > 0)
            {
                entry->expiry_time = time(NULL) + cache->ttl_seconds;
            }
        }
    }

    void *value = entry->value;
    pthread_rwlock_unlock(&cache->lock);
    return value;
}

void *lru_cache_get_n(lru_cache_t *cache, const char *key, size_t key_len)
{
    if (!cache || !key) return NULL;

    pthread_rwlock_wrlock(&cache->lock);

    if (cache->ttl_seconds > 0)
    {
        expire_lfu_entries(cache);
    }

    cache_entry_t *entry = hash_table_find_n(cache->hash_table, key, key_len);
    if (!entry)
    {
        cache->misses++;
        pthread_rwlock_unlock(&cache->lock);
        return NULL;
    }

    cache->hits++;

    entry->access_count++;

    if (entry->access_count >= cache->promotion_threshold && cache->lfu_capacity > 0)
    {
        cache_entry_t *check = cache->lru_head;
        while (check)
        {
            if (check == entry)
            {
                promote_to_lfu(cache, entry);
                break;
            }
            check = check->next;
        }
    }
    else
    {
        int in_lru = 0;
        cache_entry_t *check = cache->lru_head;
        while (check)
        {
            if (check == entry)
            {
                in_lru = 1;
                break;
            }
            check = check->next;
        }

        if (in_lru)
        {
            list_remove(&cache->lru_head, &cache->lru_tail, entry);
            list_push_front(&cache->lru_head, &cache->lru_tail, entry);
        }
        else
        {
            if (cache->ttl_seconds > 0)
            {
                entry->expiry_time = time(NULL) + cache->ttl_seconds;
            }
        }
    }

    void *value = entry->value;
    pthread_rwlock_unlock(&cache->lock);
    return value;
}

void *lru_cache_get_copy(lru_cache_t *cache, const char *key, void *(*copy_fn)(void *))
{
    if (!cache || !key || !copy_fn) return NULL;

    pthread_rwlock_wrlock(&cache->lock);

    if (cache->ttl_seconds > 0)
    {
        expire_lfu_entries(cache);
    }

    cache_entry_t *entry = hash_table_find(cache->hash_table, key);
    if (!entry)
    {
        cache->misses++;
        pthread_rwlock_unlock(&cache->lock);
        return NULL;
    }

    cache->hits++;

    void *copy = copy_fn(entry->value);

    entry->access_count++;

    if (entry->access_count >= cache->promotion_threshold && cache->lfu_capacity > 0)
    {
        cache_entry_t *check = cache->lru_head;
        while (check)
        {
            if (check == entry)
            {
                promote_to_lfu(cache, entry);
                break;
            }
            check = check->next;
        }
    }

    pthread_rwlock_unlock(&cache->lock);
    return copy;
}

void *lru_cache_get_copy_n(lru_cache_t *cache, const char *key, size_t key_len,
                           void *(*copy_fn)(void *))
{
    if (!cache || !key || !copy_fn) return NULL;

    pthread_rwlock_wrlock(&cache->lock);

    if (cache->ttl_seconds > 0)
    {
        expire_lfu_entries(cache);
    }

    cache_entry_t *entry = hash_table_find_n(cache->hash_table, key, key_len);
    if (!entry)
    {
        cache->misses++;
        pthread_rwlock_unlock(&cache->lock);
        return NULL;
    }

    cache->hits++;

    void *copy = copy_fn(entry->value);

    entry->access_count++;

    if (entry->access_count >= cache->promotion_threshold && cache->lfu_capacity > 0)
    {
        cache_entry_t *check = cache->lru_head;
        while (check)
        {
            if (check == entry)
            {
                promote_to_lfu(cache, entry);
                break;
            }
            check = check->next;
        }
    }

    pthread_rwlock_unlock(&cache->lock);
    return copy;
}

int lru_cache_remove(lru_cache_t *cache, const char *key)
{
    if (!cache || !key) return -1;

    pthread_rwlock_wrlock(&cache->lock);

    cache_entry_t *entry = hash_table_find(cache->hash_table, key);
    if (!entry)
    {
        pthread_rwlock_unlock(&cache->lock);
        return -1;
    }

    hash_table_remove(cache->hash_table, key);

    cache_entry_t *check = cache->lru_head;
    int found_in_lru = 0;
    while (check)
    {
        if (check == entry)
        {
            found_in_lru = 1;
            break;
        }
        check = check->next;
    }

    if (found_in_lru)
    {
        list_remove(&cache->lru_head, &cache->lru_tail, entry);
        cache->lru_size--;
    }
    else
    {
        list_remove(&cache->lfu_head, &cache->lfu_tail, entry);
        cache->lfu_size--;
    }

    entry_free(entry, 1);

    pthread_rwlock_unlock(&cache->lock);
    return 0;
}

void lru_cache_clear(lru_cache_t *cache)
{
    if (!cache) return;

    pthread_rwlock_wrlock(&cache->lock);

    cache_entry_t *entry = cache->lru_head;
    while (entry)
    {
        cache_entry_t *next = entry->next;
        entry_free(entry, 1);
        entry = next;
    }
    cache->lru_head = cache->lru_tail = NULL;
    cache->lru_size = 0;

    entry = cache->lfu_head;
    while (entry)
    {
        cache_entry_t *next = entry->next;
        entry_free(entry, 1);
        entry = next;
    }
    cache->lfu_head = cache->lfu_tail = NULL;
    cache->lfu_size = 0;

    hash_table_destroy(cache->hash_table);
    size_t num_buckets = (cache->lru_capacity + cache->lfu_capacity) / 4;
    if (num_buckets < 16) num_buckets = 16;
    cache->hash_table = hash_table_create(num_buckets);

    pthread_rwlock_unlock(&cache->lock);
}

void lru_cache_free(lru_cache_t *cache)
{
    if (!cache) return;

    lru_cache_clear(cache);
    hash_table_destroy(cache->hash_table);
    pthread_rwlock_destroy(&cache->lock);
    free(cache);
}

void lru_cache_destroy(lru_cache_t *cache)
{
    if (!cache) return;

    pthread_rwlock_wrlock(&cache->lock);

    cache_entry_t *entry = cache->lru_head;
    while (entry)
    {
        cache_entry_t *next = entry->next;
        entry_free(entry, 0);
        entry = next;
    }

    entry = cache->lfu_head;
    while (entry)
    {
        cache_entry_t *next = entry->next;
        entry_free(entry, 0);
        entry = next;
    }

    pthread_rwlock_unlock(&cache->lock);

    hash_table_destroy(cache->hash_table);
    pthread_rwlock_destroy(&cache->lock);
    free(cache);
}

size_t lru_cache_size(lru_cache_t *cache)
{
    if (!cache) return 0;

    pthread_rwlock_rdlock(&cache->lock);
    size_t size = cache->lru_size + cache->lfu_size;
    pthread_rwlock_unlock(&cache->lock);
    return size;
}

size_t lru_cache_capacity(lru_cache_t *cache)
{
    if (!cache) return 0;
    return cache->lru_capacity + cache->lfu_capacity;
}

void lru_cache_stats(lru_cache_t *cache, size_t *lru_size, size_t *lfu_size, uint64_t *hits,
                     uint64_t *misses)
{
    if (!cache) return;

    pthread_rwlock_rdlock(&cache->lock);
    if (lru_size) *lru_size = cache->lru_size;
    if (lfu_size) *lfu_size = cache->lfu_size;
    if (hits) *hits = cache->hits;
    if (misses) *misses = cache->misses;
    pthread_rwlock_unlock(&cache->lock);
}

static cache_entry_t *entry_create(const char *key, void *value, lru_evict_callback_t evict_cb,
                                   void *user_data)
{
    cache_entry_t *entry = (cache_entry_t *)calloc(1, sizeof(cache_entry_t));
    if (!entry) return NULL;

    entry->key = tdb_strdup(key);
    if (!entry->key)
    {
        free(entry);
        return NULL;
    }

    entry->value = value;
    entry->access_count = 1;
    entry->evict_cb = evict_cb;
    entry->user_data = user_data;
    entry->expiry_time = 0;

    return entry;
}

static void entry_free(cache_entry_t *entry, int call_callback)
{
    if (!entry) return;

    if (call_callback && entry->evict_cb && entry->value)
    {
        entry->evict_cb(entry->key, entry->value, entry->user_data);
    }

    free(entry->key);
    free(entry);
}

static void list_remove(cache_entry_t **head, cache_entry_t **tail, cache_entry_t *entry)
{
    if (!entry) return;

    if (entry->prev)
        entry->prev->next = entry->next;
    else
        *head = entry->next;

    if (entry->next)
        entry->next->prev = entry->prev;
    else
        *tail = entry->prev;

    entry->prev = entry->next = NULL;
}

static void list_push_front(cache_entry_t **head, cache_entry_t **tail, cache_entry_t *entry)
{
    if (!entry) return;

    entry->next = *head;
    entry->prev = NULL;

    if (*head)
        (*head)->prev = entry;
    else
        *tail = entry;

    *head = entry;
}

static void evict_lru_entry(lru_cache_t *cache)
{
    if (!cache->lru_tail) return;

    cache_entry_t *victim = cache->lru_tail;

    hash_table_remove(cache->hash_table, victim->key);

    list_remove(&cache->lru_head, &cache->lru_tail, victim);
    cache->lru_size--;

    entry_free(victim, 1);
}

static void evict_lfu_entry(lru_cache_t *cache)
{
    if (!cache->lfu_tail) return;

    cache_entry_t *victim = cache->lfu_tail;

    hash_table_remove(cache->hash_table, victim->key);

    list_remove(&cache->lfu_head, &cache->lfu_tail, victim);
    cache->lfu_size--;

    entry_free(victim, 1);
}

static void promote_to_lfu(lru_cache_t *cache, cache_entry_t *entry)
{
    list_remove(&cache->lru_head, &cache->lru_tail, entry);
    cache->lru_size--;

    if (cache->lfu_size >= cache->lfu_capacity)
    {
        evict_lfu_entry(cache);
    }

    if (cache->ttl_seconds > 0)
    {
        entry->expiry_time = time(NULL) + cache->ttl_seconds;
    }

    list_push_front(&cache->lfu_head, &cache->lfu_tail, entry);
    cache->lfu_size++;
}

static void expire_lfu_entries(lru_cache_t *cache)
{
    time_t now = time(NULL);
    cache_entry_t *entry = cache->lfu_tail;

    while (entry)
    {
        cache_entry_t *prev = entry->prev;

        if (entry->expiry_time > 0 && entry->expiry_time <= now)
        {
            hash_table_remove(cache->hash_table, entry->key);
            list_remove(&cache->lfu_head, &cache->lfu_tail, entry);
            cache->lfu_size--;

            entry_free(entry, 1);
        }

        entry = prev;
    }
}

static uint64_t hash_string(const char *str)
{
    return XXH64(str, strlen(str), 0);
}

static uint64_t hash_string_n(const char *str, size_t len)
{
    return XXH64(str, len, 0);
}

static hash_table_t *hash_table_create(size_t num_buckets)
{
    hash_table_t *ht = (hash_table_t *)calloc(1, sizeof(hash_table_t));
    if (!ht) return NULL;

    ht->buckets = (hash_bucket_t *)calloc(num_buckets, sizeof(hash_bucket_t));
    if (!ht->buckets)
    {
        free(ht);
        return NULL;
    }

    ht->num_buckets = num_buckets;
    return ht;
}

static void hash_table_destroy(hash_table_t *ht)
{
    if (!ht) return;

    for (size_t i = 0; i < ht->num_buckets; i++)
    {
        free(ht->buckets[i].entries);
    }
    free(ht->buckets);
    free(ht);
}

static cache_entry_t *hash_table_find(hash_table_t *ht, const char *key)
{
    if (!ht || !key) return NULL;

    uint64_t hash = hash_string(key);
    size_t bucket_idx = hash % ht->num_buckets;
    hash_bucket_t *bucket = &ht->buckets[bucket_idx];

    for (size_t i = 0; i < bucket->count; i++)
    {
        if (strcmp(bucket->entries[i]->key, key) == 0)
        {
            return bucket->entries[i];
        }
    }

    return NULL;
}

static cache_entry_t *hash_table_find_n(hash_table_t *ht, const char *key, size_t key_len)
{
    if (!ht || !key) return NULL;

    uint64_t hash = hash_string_n(key, key_len);
    size_t bucket_idx = hash % ht->num_buckets;
    hash_bucket_t *bucket = &ht->buckets[bucket_idx];

    for (size_t i = 0; i < bucket->count; i++)
    {
        if (strcmp(bucket->entries[i]->key, key) == 0)
        {
            return bucket->entries[i];
        }
    }

    return NULL;
}

static int hash_table_insert(hash_table_t *ht, cache_entry_t *entry)
{
    if (!ht || !entry) return -1;

    uint64_t hash = hash_string(entry->key);
    size_t bucket_idx = hash % ht->num_buckets;
    hash_bucket_t *bucket = &ht->buckets[bucket_idx];

    /* grow bucket if needed */
    if (bucket->count >= bucket->capacity)
    {
        size_t new_capacity = bucket->capacity == 0 ? 4 : bucket->capacity * 2;
        cache_entry_t **new_entries =
            (cache_entry_t **)realloc(bucket->entries, new_capacity * sizeof(cache_entry_t *));
        if (!new_entries) return -1;

        bucket->entries = new_entries;
        bucket->capacity = new_capacity;
    }

    bucket->entries[bucket->count++] = entry;
    return 0;
}

static void hash_table_remove(hash_table_t *ht, const char *key)
{
    if (!ht || !key) return;

    uint64_t hash = hash_string(key);
    size_t bucket_idx = hash % ht->num_buckets;
    hash_bucket_t *bucket = &ht->buckets[bucket_idx];

    for (size_t i = 0; i < bucket->count; i++)
    {
        if (strcmp(bucket->entries[i]->key, key) == 0)
        {
            /* shift remaining entries */
            for (size_t j = i; j < bucket->count - 1; j++)
            {
                bucket->entries[j] = bucket->entries[j + 1];
            }
            bucket->count--;
            return;
        }
    }
}

size_t lru_cache_foreach(lru_cache_t *cache, lru_foreach_callback_t callback, void *user_data)
{
    if (!cache || !callback) return 0;

    pthread_rwlock_rdlock(&cache->lock);

    size_t count = 0;

    /* iter over LRU cache first */
    cache_entry_t *entry = cache->lru_head;
    while (entry)
    {
        int result = callback(entry->key, entry->value, user_data);
        count++;

        if (result != 0)
        {
            /* stop iteration */
            pthread_rwlock_unlock(&cache->lock);
            return count;
        }

        entry = entry->next;
    }

    /* then iterate over LFU cache */
    entry = cache->lfu_head;
    while (entry)
    {
        int result = callback(entry->key, entry->value, user_data);
        count++;

        if (result != 0)
        {
            /* stop iteration */
            pthread_rwlock_unlock(&cache->lock);
            return count;
        }

        entry = entry->next;
    }

    pthread_rwlock_unlock(&cache->lock);
    return count;
}
