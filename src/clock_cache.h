#ifndef __CACHE_H__
#define __CACHE_H__
#include "compat.h"

/* forward declarations */
typedef struct clock_cache_t clock_cache_t;
typedef struct clock_cache_entry_t clock_cache_entry_t;
typedef struct clock_cache_hash_bucket_t clock_cache_hash_bucket_t;

/* special slot ID value indicating invalid/no slot */
#define CACHE_INVALID_SLOT_ID ((uint32_t)-1)

/* eviction thread states */
#define CACHE_EVICTION_RUNNING 0
#define CACHE_EVICTION_STOPPED 1

/* default eviction parameters */
#define CACHE_DEFAULT_EVICTION_INTERVAL_MS 50   /* check every 50ms (more responsive) */
#define CACHE_DEFAULT_MAX_BACKOFF_MS       1000 /* max 1 second (fail faster) */
#define CACHE_DEFAULT_EVICTION_THRESHOLD   0.85 /* evict when 85% full (earlier) */
#define CACHE_DEFAULT_EVICTION_TARGET      0.60 /* evict down to 60% (more aggressive) */
#define CACHE_DEFAULT_HASH_BUCKETS         0    /* 0 = auto-calculate based on cache size */

/* dynamic scaling parameters */
#define CACHE_MIN_HASH_BUCKETS 4096 /* minimum buckets (2^12) -- higher for better distribution */
#define CACHE_MAX_HASH_BUCKETS 16777216 /* maximum buckets (2^24 = 16M) */
#define CACHE_TARGET_LOAD_FACTOR \
    2.0 /* target 2.0 load factor (fewer buckets, less memory, less contention) */
#define CACHE_ESTIMATED_ENTRY_SIZE 100

/* hash chain insertion parameters */
#define CACHE_INITIAL_BACKOFF          1   /* initial backoff for CAS retry */
#define CACHE_MAX_INSERT_RETRIES       100 /* maximum retries for hash chain insertion */
#define CACHE_LOW_CONTENTION_THRESHOLD 10  /* retry count for low contention (pause only) */
#define CACHE_MED_CONTENTION_THRESHOLD \
    50 /* retry count for medium contention (exponential backoff) */
#define CACHE_MAX_BACKOFF_PAUSES       128 /* maximum pause iterations in backoff */
#define CACHE_HIGH_CONTENTION_SLEEP_US 1   /* sleep duration in microseconds for high contention */

/* memory pool parameters */
#define CACHE_MIN_POOL_SIZE (1024 * 1024) /* 1 MB minimum cache size to enable memory pool */

/**
 * clock_cache_entry_t
 * a single cache entry stored in a buffer slot
 * cache aligned -- padded to 64 bytes to prevent false sharing
 * @param key pointer to key data
 * @param key_len length of key
 * @param payload pointer to payload data
 * @param payload_len length of payload
 * @param last_access_ns last access timestamp in nanoseconds
 * @param hash hash value of the key
 * @param next_in_bucket next entry in hash chain (slot ID)
 * @param ref_bit CLOCK: 1 = recently accessed, 0 = candidate for eviction
 * @param from_pool 1 if allocated from pool, 0 if malloc
 * @param _padding padding to align to cache line
 */
struct clock_cache_entry_t
{
    uint8_t *key;
    size_t key_len;
    uint8_t *payload;
    size_t payload_len;
    uint64_t hash;
    _Atomic(uint32_t) next_in_bucket;
    _Atomic(uint8_t) ref_bit;
    uint8_t from_pool;
    uint8_t _padding[6];
};

/**
 * clock_cache_hash_bucket_t
 * hash table bucket for O(1) lookups
 * cache aligned -- padded to 64 bytes to prevent false sharing between buckets
 * @param head_slot_id first entry in chain (buffer slot ID)
 * @param _padding padding to align to cache line
 */
struct clock_cache_hash_bucket_t
{
    _Atomic(uint32_t) head_slot_id;
    uint8_t _padding[60];
} __attribute__((aligned(64)));

/**
 * clock_cache_entry_pool_node_t
 * node in the memory pool for cache entries
 * @param next pointer to next node in free list
 * @param data flexible array for entry + key + payload
 */
typedef struct clock_cache_entry_pool_node_t
{
    struct clock_cache_entry_pool_node_t *next;
    uint8_t data[]; /* flexible array for entry + key + payload */
} clock_cache_entry_pool_node_t;

/**
 * clock_cache_entry_pool_t
 * lock-free memory pool for cache entries
 * @param free_list lock-free free list
 * @param node_size size of each pool node
 * @param max_nodes maximum pool size
 * @param allocated_nodes current allocated count
 * @param pool_hits pool allocation hits
 * @param pool_misses fallback to malloc
 */
typedef struct
{
    _Atomic(clock_cache_entry_pool_node_t *) free_list;
    size_t node_size;
    size_t max_nodes;
    _Atomic(size_t) allocated_nodes;
    _Atomic(size_t) pool_hits;
    _Atomic(size_t) pool_misses;
} clock_cache_entry_pool_t;

/**
 * clock_cache_slot_t
 * Simple fixed-size slot for O(1) allocation
 * cache aligned -- padded to 64 bytes to prevent false sharing between slots
 * @param entry pointer to cache entry (NULL = free, non-NULL = occupied)
 * @_padding padding to align to cache line
 */
typedef struct
{
    _Atomic(clock_cache_entry_t *) entry;
    uint8_t _padding[56];
} __attribute__((aligned(64))) clock_cache_slot_t;

/**
 * clock_cache_t
 * main cache structure with automated eviction
 * @param slots fixed array of slots
 * @param num_slots total slots
 * @param next_slot next slot to try (round-robin)
 * @param active_slots number of occupied slots
 * @param clock_hand CLOCK: current position for eviction sweep
 * @param hash_table hash table for O(1) lookups
 * @param num_buckets number of hash buckets
 * @param max_bytes maximum cache size in bytes
 * @param current_bytes current cache size in bytes
 * @param entry_pool lock-free memory pool for cache entries
 * @param eviction_thread background eviction thread
 * @param eviction_state eviction thread state
 * @param eviction_interval_ms eviction check interval
 * @param max_backoff_ms maximum backoff interval
 * @param eviction_threshold eviction trigger threshold (0.0-1.0)
 * @param eviction_target eviction target threshold (0.0-1.0)
 */
struct clock_cache_t
{
    clock_cache_slot_t *slots;
    uint32_t num_slots;
    _Atomic(uint32_t) next_slot;
    _Atomic(uint32_t) active_slots;
    _Atomic(uint32_t) clock_hand;

    clock_cache_hash_bucket_t *hash_table;
    uint32_t num_buckets;
    size_t max_bytes;
    _Atomic(size_t) current_bytes;
    clock_cache_entry_pool_t *entry_pool;
    pthread_t eviction_thread;
    _Atomic(uint32_t) eviction_state;
    uint32_t eviction_interval_ms;
    uint32_t max_backoff_ms;
    float eviction_threshold;
    float eviction_target;
};

/**
 * cache_config_t
 * Configuration for cache creation with dynamic hash table sizing
 *
 * DYNAMIC HASH TABLE SIZING **
 * when num_buckets = 0, the cache automatically calculates optimal bucket count:
 *   - estimates max entries -- max_bytes / 256 (conservative avg entry size)
 *   - targets 75% load factor for optimal performance
 *   - rounds to power-of-2 for fast modulo (bitwise AND)
 *   - range -- 1,024 (min) to 16,777,216 (max)
 *
 * PERFORMANCE **
 *   - power-of-2 buckets enable 10-20x faster hash lookups (AND vs modulo)
 *   - auto-sizing saves memory while maintaining O(1) performance
 *   - load factor 0.75 balances memory usage vs chain length
 *
 * EXAMPLES **
 *   64 MB cache  -> 262,144 buckets (2^18) -> ~1 MB hash table
 *   256 MB cache -> 1,048,576 buckets (2^20) -> ~4 MB hash table
 *   1 GB cache   -> 4,194,304 buckets (2^22) -> ~16 MB hash table
 */
typedef struct
{
    size_t max_bytes;              /* maximum cache size in bytes */
    uint32_t num_slots;            /* number of buffer slots (0 = auto) */
    uint32_t num_buckets;          /* number of hash buckets (0 = auto-calculate) */
    uint32_t eviction_interval_ms; /* eviction check interval (0 = default) */
    uint32_t max_backoff_ms;       /* max backoff interval (0 = default) */
    float eviction_threshold;      /* trigger eviction at this fill ratio (0 = default) */
    float eviction_target;         /* evict down to this ratio (0 = default) */
} cache_config_t;

/**
 * clock_cache_create
 * create a new cache
 * @param config cache configuration
 * @return pointer to cache or NULL on failure
 */
clock_cache_t *clock_cache_create(const cache_config_t *config);

/**
 * clock_cache_destroy
 * destroy the cache
 * @param cache cache to destroy
 */
void clock_cache_destroy(clock_cache_t *cache);

/**
 * clock_cache_put
 * put a key-value pair into the cache
 * @param cache cache instance
 * @param key key string
 * @param key_len key length
 * @param payload payload bytes
 * @param payload_len payload length
 * @return 0 on success, -1 on failure
 */
int clock_cache_put(clock_cache_t *cache, const char *key, size_t key_len, const uint8_t *payload,
                    size_t payload_len);

/**
 * clock_cache_get
 * get a value from the cache
 * @param cache cache instance
 * @param key key string
 * @param key_len key length
 * @param payload_len output parameter for payload length
 * @return pointer to payload (caller must free) or NULL if not found
 */
uint8_t *clock_cache_get(clock_cache_t *cache, const char *key, size_t key_len,
                         size_t *payload_len);

/**
 * clock_cache_delete
 * delete a key-value pair from the cache
 * @param cache cache instance
 * @param key key string
 * @param key_len key length
 * @return 0 on success, -1 if not found
 */
int clock_cache_delete(clock_cache_t *cache, const char *key, size_t key_len);

/**
 * clock_cache_exists
 * check if a key exists in the cache
 * @param cache cache instance
 * @param key key string
 * @param key_len key length
 * @return 1 if exists, 0 if not
 */
int clock_cache_exists(clock_cache_t *cache, const char *key, size_t key_len);

/**
 * clock_cache_clear
 * clear all entries from the cache
 * @param cache cache instance
 */
void clock_cache_clear(clock_cache_t *cache);

/**
 * clock_cache_stats
 * get cache statistics
 * @param cache cache instance
 * @param total_entries output for total number of entries
 * @param total_bytes output for total bytes used
 */
void clock_cache_stats(clock_cache_t *cache, size_t *total_entries, size_t *total_bytes);

/**
 * clock_cache_stats_detailed
 * get detailed cache statistics including hash table metrics
 * @param cache cache instance
 * @param total_entries output for total number of entries
 * @param total_bytes output for total bytes used
 * @param num_buckets output for number of hash buckets
 * @param load_factor output for current load factor (entries/buckets)
 */
void clock_cache_stats_detailed(clock_cache_t *cache, size_t *total_entries, size_t *total_bytes,
                                uint32_t *num_buckets, float *load_factor);

/**
 * clock_cache_stats_pool
 * get memory pool statistics
 * @param cache cache instance
 * @param pool_hits output for number of pool allocations
 * @param pool_misses output for number of malloc fallbacks
 * @param pool_allocated output for current allocated pool nodes
 * @param pool_max output for maximum pool size
 * @param pool_hit_rate Output for pool hit rate (0.0-1.0)
 */
void clock_cache_stats_pool(clock_cache_t *cache, size_t *pool_hits, size_t *pool_misses,
                            size_t *pool_allocated, size_t *pool_max, float *pool_hit_rate);

#endif /* __CACHE_H__ */