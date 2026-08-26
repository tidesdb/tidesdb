/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __SKIP_LIST_H__
#define __SKIP_LIST_H__
#include "base/arena.h" /* the shared region allocator backing node and version storage */
#include "compat.h"

/* branch prediction hints for hot paths */
#if defined(__GNUC__) || defined(__clang__)
#define SKIP_LIST_LIKELY(x)   __builtin_expect(!!(x), 1)
#define SKIP_LIST_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define SKIP_LIST_LIKELY(x)   (x)
#define SKIP_LIST_UNLIKELY(x) (x)
#endif

/* forward declarations */
typedef struct skip_list_node_t skip_list_node_t;
typedef struct skip_list_t skip_list_t;
typedef struct skip_list_version_t skip_list_version_t;
/* alignment for node and version allocations drawn from the arena */
#define SKIP_LIST_ARENA_ALIGNMENT 8

/* skip_list_version_t flag bits */
#define SKIP_LIST_FLAG_DELETED 0x01 /* version is tombstone */
#define SKIP_LIST_FLAG_SINGLE_DELETE                         \
    0x02 /* tombstone subtype, always set together with      \
          * SKIP_LIST_FLAG_DELETED. caller promises the key  \
          * has been put at most once since the last         \
          * single-delete or start, so put+single-delete can \
          * be reaped together at compaction. */
#define SKIP_LIST_FLAG_VLOG_REF                                \
    0x04 /* the version's bytes live in the shared value log   \
          * rather than in the version. its value pointer is   \
          * NULL and value_size is the logical length, and the \
          * id sits in the tail of the same allocation, which  \
          * skip_list_version_vlog_id reads. a reader that     \
          * ignores this bit sees an empty value, so every     \
          * getter reports the id alongside the value. */

/* skip_list_node_t flag bits */
#define SKIP_LIST_NODE_FLAG_SENTINEL 0x01 /* node is a sentinel (header or tail) */

#define SKIP_LIST_MAX_CAS_ATTEMPTS 1000

/* a lookup walks the level-0 chain forward from the predecessor its descent settled on, because an
 * insert can splice a smaller key in between. the walk needs at most one hop per node lying between
 * the two, which the list's own entry count bounds; this is the slack added on top, covering nodes
 * spliced in while the walk is running. the bound is derived from the structure rather than fixed
 * outright so that exhausting it means one thing only -- the list grew underneath this descent */
#define SKIP_LIST_FORWARD_HOP_SLACK 64

/* how many times a lookup re-descends when that walk runs out of budget. exhausting it is not an
 * absence, so the descent is taken again from the top, where the predecessor it settles on is much
 * closer to the key than the stale one was -- which is why restarting converges instead of merely
 * retrying. bounded so the lookup can never spin */
#define SKIP_LIST_MAX_FIND_RESTARTS 4

/* how many times an insert restarts its walk from the header after exhausting the cas budget at one
 * position; the product bounds the work while keeping a contended write from being dropped */
#define SKIP_LIST_MAX_INSERT_RESTARTS 8

/* helper macros for flag access */
#define VERSION_IS_DELETED(version) \
    (atomic_load_explicit(&(version)->flags, memory_order_acquire) & SKIP_LIST_FLAG_DELETED)

#define NODE_IS_SENTINEL(node) ((node)->node_flags & SKIP_LIST_NODE_FLAG_SENTINEL)

/**
 * skip_list_version_t
 * a single version of a key's value
 * @seq sequence number for MVCC (monotonically increasing)
 * @value value data
 * @value_size size of value
 * @ttl time-to-live
 * @next next older version
 * @flags version flags (deleted, etc)
 */
struct skip_list_version_t
{
    _Atomic(uint64_t) seq;
    uint8_t *value;
    size_t value_size;
    int64_t ttl;
    _Atomic(skip_list_version_t *) next;
    _Atomic(uint8_t) flags;
};

/* macro to access backward pointers at a specific level */
#define BACKWARD_PTR(node, lvl, max_level) (node->forward[(max_level) + 1 + (lvl)])

/* each node keeps two parallel pointer arrays of (level + 1) entries -- forward links followed by
 * backward links -- so its combined pointer region holds this many slots */
#define SKIP_LIST_NODE_PTR_SLOTS(level) ((size_t)(2 * ((level) + 1)))

/* what an allocation of this size actually takes from the arena, which hands back a region aligned
 * the way the caller asked. the tail of a key or a value lands mid-word, so charging the unrounded
 * size would under-count every entry by a few bytes */
#define SKIP_LIST_ALLOC_BYTES(size) \
    (((size) + (size_t)SKIP_LIST_ARENA_ALIGNMENT - 1) & ~((size_t)SKIP_LIST_ARENA_ALIGNMENT - 1))

/* the bytes a version occupies once resident -- its struct plus whatever follows it in the same
 * allocation, which is the value for an inline version and the eight byte value log id for a
 * referenced one. charging only the value would make a tombstone, or a put of an empty value, free
 * to the size the rotation threshold reads, and a key written that way repeatedly would grow its
 * chain without the memtable ever sealing */
#define SKIP_LIST_VERSION_BYTES(tail_size) \
    SKIP_LIST_ALLOC_BYTES(sizeof(skip_list_version_t) + (tail_size))

/**
 * skip_list_version_tail_bytes
 * how many bytes follow the version struct in its allocation -- the value for an inline version,
 * the eight byte id for a referenced one, and nothing for a tombstone. SKIP_LIST_FLAG_VLOG_REF is
 * the single thing that decides which, here and everywhere else, so a caller that leaves vlog_id
 * unset on an inline entry cannot be misread as referencing something
 * @param value the inline value bytes, NULL when referenced or absent
 * @param value_size the value's logical length
 * @param flags the version's SKIP_LIST_FLAG_* bits
 * @return the tail length in bytes
 */
static inline size_t skip_list_version_tail_bytes(const uint8_t *value, const size_t value_size,
                                                  const uint8_t flags)
{
    if (flags & SKIP_LIST_FLAG_VLOG_REF) return sizeof(uint64_t);
    return (value != NULL && value_size > 0) ? value_size : 0;
}

/**
 * skip_list_version_vlog_id
 * the value log id a referenced version carries, read from the tail of its allocation
 * @param version the version to read, must not be NULL
 * @return the id, or 0 when the version holds its value inline
 */
static inline uint64_t skip_list_version_vlog_id(const skip_list_version_t *version)
{
    if (!(atomic_load_explicit(&version->flags, memory_order_acquire) & SKIP_LIST_FLAG_VLOG_REF))
        return 0;
    uint64_t id;
    memcpy(&id, (const uint8_t *)version + sizeof(skip_list_version_t), sizeof(id));
    return id;
}

/* the bytes a node occupies once resident. skip_list_build_node lays the header, both pointer
 * arrays and the key down in one allocation, so this is that allocation. the key and the value are
 * a fraction of it at the sizes a memtable holds -- the header and the two pointer arrays are
 * around eighty bytes whatever the entry, which is why a memtable that counts only key and value
 * bytes holds several times the memory its configured size asks for */
#define SKIP_LIST_NODE_BYTES(level, key_size)                                                     \
    SKIP_LIST_ALLOC_BYTES(sizeof(skip_list_node_t) +                                              \
                          SKIP_LIST_NODE_PTR_SLOTS(level) * sizeof(_Atomic(skip_list_node_t *)) + \
                          (key_size))

/**
 * skip_list_node_t
 * a key in the skip list with multiple versions
 * @level node level in skip list
 * @node_flags node flags (sentinel, etc)
 * @key key data (NULL for sentinel nodes)
 * @key_size size of key (0 for sentinel nodes)
 * @versions lock-free list of versions (newest first)
 * @forward forward[0..level] forward pointers, forward[level+1..2*level+1] backward pointers
 */
struct skip_list_node_t
{
    uint8_t level;
    uint8_t node_flags;
    uint8_t *key;
    size_t key_size;
    _Atomic(skip_list_version_t *) versions;

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4200)
#endif
    _Atomic(skip_list_node_t *) forward[];
#ifdef _MSC_VER
#pragma warning(pop)
#endif
};

/**
 * skip_list_t
 * main skip list structure
 * @level current maximum level
 * @max_level maximum allowed level
 * @probability probability for level generation
 * @header sentinel header node (compares less than all keys)
 * @tail sentinel tail node (compares greater than all keys)
 * @data_bytes logical key and value bytes held, which is roughly what flushing the list writes
 * @memory_bytes bytes the list actually occupies -- nodes, both pointer arrays, keys, version
 * structs and values. this is what the rotation threshold reads, since a memtable is a memory
 * budget rather than a promise about output size
 * @entry_count track entry count atomically to avoid O(n) traversals
 * @cached_time borrowed clock published by a ticker, read instead of calling time(NULL) on every
 * expiry test (NULL = call time(NULL) directly)
 * @arena bump allocator for cache-friendly node allocation (NULL = use malloc/free)
 * @min_seq smallest sequence number ever inserted (UINT64_MAX when empty). lets a compaction learn
 * the oldest unflushed write held in a memtable so it never reaps a tombstone newer than data that
 * has not yet reached disk
 */
typedef struct skip_list_t
{
    _Atomic(int) level;
    int max_level;
    float probability;
    _Atomic(skip_list_node_t *) header;
    _Atomic(skip_list_node_t *) tail;
    _Atomic(size_t) data_bytes;
    _Atomic(size_t) memory_bytes;
    _Atomic(int) entry_count;
    _Atomic(int64_t) *cached_time;
    arena_t *arena;
    _Atomic(uint64_t) min_seq;
} skip_list_t;

/**
 * skip_list_cursor_t
 * cursor structure for iterating through the skip list
 * @list pointer to the skip list
 * @current current node position
 * @cached_header cached header sentinel for fast boundary checks
 * @cached_tail cached tail sentinel for fast boundary checks
 * @current_version current version on the current node; NULL means use head.
 *                        advanced by skip_list_cursor_advance_in_node and reset on
 *                        every cursor seek/next/prev
 */
typedef struct
{
    skip_list_t *list;
    skip_list_node_t *current;
    skip_list_node_t *cached_header;
    skip_list_node_t *cached_tail;
    skip_list_version_t *current_version;
} skip_list_cursor_t;

/**
 * skip_list_create_node
 * creates a new skip list node
 * @param level level of the node
 * @param key key data
 * @param key_size size of key
 * @param value value data
 * @param value_size size of value
 * @param ttl time-to-live
 * @param flags version flags (bitmask of SKIP_LIST_FLAG_*)
 * @return pointer to new node, NULL on failure
 */
skip_list_node_t *skip_list_create_node(int level, const uint8_t *key, size_t key_size,
                                        const uint8_t *value, size_t value_size, int64_t ttl,
                                        uint8_t flags);

/**
 * skip_list_free_node
 * frees a skip list node
 * @param node node to free
 * @return 0 on success, -1 on failure
 */
int skip_list_free_node(skip_list_node_t *node);

/**
 * skip_list_new
 * creates a new skip list; keys are ordered byte-wise
 * @param list pointer to skip list pointer
 * @param max_level maximum level
 * @param probability probability for level generation
 * @return 0 on success, -1 on failure
 */
int skip_list_new(skip_list_t **list, int max_level, float probability);

/**
 * skip_list_new_with_arena
 * creates a new skip list whose node and version memory is bump-allocated from a concurrent arena
 * over the shared pool, improving traversal locality; individual frees are no-ops and all memory is
 * reclaimed when the skip list is freed, so this is the memtable shape (filled by many writers,
 * freed whole)
 * @param list out -- the new skip list on success
 * @param max_level maximum level
 * @param probability probability for level generation
 * @param cached_time borrowed clock read instead of time(NULL), or NULL to call it directly
 * @param pool the shared chunk pool the arena draws from, or NULL for an arena that allocates
 * chunks directly without recycling
 * @return 0 on success, -1 on failure
 */
int skip_list_new_with_arena(skip_list_t **list, int max_level, float probability,
                             _Atomic(int64_t) *cached_time, arena_pool_t *pool);

/**
 * skip_list_random_level
 * generates a random level for a new node
 * @param list skip list
 * @return random level, or -1 if list is NULL
 */
int skip_list_random_level(const skip_list_t *list);

/**
 * skip_list_compare_keys
 * compares two keys byte-wise
 * @param list skip list
 * @param key1 first key
 * @param key1_size size of first key
 * @param key2 second key
 * @param key2_size size of second key
 * @return negative if key1 < key2, 0 if equal (or if list/key is NULL), positive if key1 > key2
 */
int skip_list_compare_keys(const skip_list_t *list, const uint8_t *key1, size_t key1_size,
                           const uint8_t *key2, size_t key2_size);

/**
 * skip_list_put_with_seq
 * inserts or updates a key-value pair with a specific sequence number
 * @param list skip list
 * @param key key
 * @param key_size key size
 * @param value value
 * @param value_size value size
 * @param ttl time-to-live
 * @param seq sequence number for MVCC
 * @param flags bitmask of SKIP_LIST_FLAG_*; 0 means a live put, SKIP_LIST_FLAG_DELETED
 *              means a tombstone, optionally OR'd with SKIP_LIST_FLAG_SINGLE_DELETE.
 *              passing 1 for a regular tombstone remains valid because the value 1
 *              equals SKIP_LIST_FLAG_DELETED.
 * @return 0 on success, -1 on failure
 */
int skip_list_put_with_seq(skip_list_t *list, const uint8_t *key, size_t key_size,
                           const uint8_t *value, size_t value_size, int64_t ttl, uint64_t seq,
                           uint8_t flags);

/**
 * skip_list_put_with_seq_tracked
 * the same insert-or-update as skip_list_put_with_seq, additionally reporting whether the put grew
 * the set of distinct keys, so a caller can maintain a per-family key count
 * @param list skip list
 * @param key key
 * @param key_size key size
 * @param value value
 * @param value_size value size
 * @param ttl time-to-live
 * @param seq sequence number for MVCC
 * @param flags bitmask of SKIP_LIST_FLAG_*, as in skip_list_put_with_seq
 * @param out_created set to 1 when the put created a new distinct key node, 0 when it added a
 *                    version to an existing key, left untouched on failure; may be NULL
 * @return 0 on success, -1 on failure
 */
int skip_list_put_with_seq_tracked(skip_list_t *list, const uint8_t *key, size_t key_size,
                                   const uint8_t *value, size_t value_size, int64_t ttl,
                                   uint64_t seq, uint8_t flags, int *out_created);

/**
 * skip_list_put_reference_with_seq
 * put a key whose value lives in the shared value log rather than in the memtable, storing the id
 * and the logical length in place of the bytes. SKIP_LIST_FLAG_VLOG_REF is set on the version, so
 * every getter reports the id and no reader mistakes the absent bytes for an empty value
 * @param list skip list
 * @param key key data
 * @param key_size size of key
 * @param vlog_id the value log entry holding the bytes, must be non-zero
 * @param value_size the value's logical length
 * @param ttl absolute expiry time, or -1 for none
 * @param seq sequence number for this version
 * @param flags bitmask of SKIP_LIST_FLAG_*, as in skip_list_put_with_seq; a tombstone references
 *              nothing, so SKIP_LIST_FLAG_DELETED is rejected here
 * @param out_created set to 1 when the put created a new distinct key node, 0 when it added a
 *                    version to an existing key, left untouched on failure; may be NULL
 * @return 0 on success, -1 on failure
 */
int skip_list_put_reference_with_seq(skip_list_t *list, const uint8_t *key, size_t key_size,
                                     uint64_t vlog_id, size_t value_size, int64_t ttl, uint64_t seq,
                                     uint8_t flags, int *out_created);

/**
 * skip_list_delete
 * deletes a key (creates tombstone) with a specific sequence number
 * @param list skip list
 * @param key key data
 * @param key_size size of key
 * @param seq sequence number for the tombstone; must differ from every existing version of the
 *            key, but need not exceed them (out-of-order seqs splice into the chain)
 * @return 0 on success or when the key is absent (no-op), -1 only on a duplicate seq or
 *         allocation failure
 */
int skip_list_delete(skip_list_t *list, const uint8_t *key, size_t key_size, uint64_t seq);

/**
 * skip_list_batch_entry_t
 * entry for batch put operations
 * @param key key data
 * @param key_size size of key
 * @param value value data (NULL for a tombstone, and for a value held in the value log)
 * @param value_size size of value (0 for tombstones), the logical length whether the bytes are
 *                   here or in the value log
 * @param vlog_id the value log entry holding this value, read only when the entry's flags carry
 *                SKIP_LIST_FLAG_VLOG_REF, which is what makes it a reference at all
 * @param seq sequence number for this entry (MVCC version)
 * @param ttl time-to-live (0 = no expiry)
 * @param flags bitmask of SKIP_LIST_FLAG_* (see below)
 *
 * flags is a bitmask of SKIP_LIST_FLAG_*. a live put leaves flags = 0; a regular
 * tombstone sets SKIP_LIST_FLAG_DELETED; a single-delete tombstone also sets
 * SKIP_LIST_FLAG_SINGLE_DELETE on top.
 */
typedef struct
{
    const uint8_t *key;
    size_t key_size;
    const uint8_t *value;
    size_t value_size;
    uint64_t seq;
    int64_t ttl;
    uint8_t flags;
    uint64_t vlog_id;
} skip_list_batch_entry_t;

/**
 * skip_list_put_batch
 * inserts multiple key-value pairs in a batch for better performance
 * entries should ideally be sorted by key for optimal performance
 * @param list skip list
 * @param entries array of batch entries
 * @param count number of entries
 * @return number of successfully inserted entries; this MAY be less than count when
 *         individual entries are skipped (e.g. duplicate (key,seq) or a per-entry
 *         allocation failure) -- compare the result against count to detect a partial
 *         batch. returns -1 only on a critical failure that inserts nothing, NULL list/
 *         entries, count == 0, or the update-array allocation failing.
 */
int skip_list_put_batch(skip_list_t *list, const skip_list_batch_entry_t *entries, size_t count);

/**
 * skip_list_get
 * retrieves a value by key
 * @param list skip list
 * @param key key data
 * @param key_size size of key
 * @param value pointer to value pointer (caller must free)
 * @param value_size pointer to value size
 * @param ttl pointer to ttl
 * @param deleted pointer to deleted flag
 * @return 0 on success, -1 on failure
 */
int skip_list_get(skip_list_t *list, const uint8_t *key, size_t key_size, uint8_t **value,
                  size_t *value_size, int64_t *ttl, uint8_t *deleted);

/**
 * skip_list_get_ref
 * zero-copy get that returns a direct pointer into the version data
 * the returned pointers are only valid while the caller holds a reference
 * to the skip list (e.g. memtable refcount). caller must not free the value.
 * @param list skip list
 * @param key key data
 * @param key_size size of key
 * @param value pointer to value pointer (do not free)
 * @param value_size pointer to value size
 * @param ttl pointer to ttl
 * @param deleted pointer to deleted flag
 * @return 0 on success, -1 on failure
 */
int skip_list_get_ref(skip_list_t *list, const uint8_t *key, size_t key_size, const uint8_t **value,
                      size_t *value_size, int64_t *ttl, uint8_t *deleted);

/**
 * skip_list_visibility_check_fn
 * whether a sequence is visible to the reader the context describes
 * @param opaque_ctx opaque context pointer (e.g., commit_status)
 * @param seq sequence number to check
 * @return 1 if visible, 0 if not
 */
typedef int (*skip_list_visibility_check_fn)(void *opaque_ctx, uint64_t seq);

/**
 * skip_list_get_with_seq
 * retrieves a value by key with sequence number for MVCC snapshot reads
 * @param list skip list
 * @param key key data
 * @param key_size size of key
 * @param value pointer to value pointer (caller must free)
 * @param value_size pointer to value size
 * @param ttl pointer to ttl
 * @param deleted pointer to deleted flag
 * @param seq pointer to sequence number (output)
 * @param snapshot_seq snapshot sequence number. UINT64_MAX reads the latest version with no
 *                     snapshot filtering; any other value reads the newest version with seq <=
 *                     snapshot_seq, so 0 matches nothing because sequence numbers start at 1
 * @param visibility_check callback to check if a sequence is committed (NULL = skip check)
 * @param visibility_ctx context for visibility check callback
 * @return 0 on success, -1 on failure
 */
int skip_list_get_with_seq(skip_list_t *list, const uint8_t *key, size_t key_size, uint8_t **value,
                           size_t *value_size, uint64_t *vlog_id, int64_t *ttl, uint8_t *deleted,
                           uint64_t *seq, uint64_t snapshot_seq,
                           skip_list_visibility_check_fn visibility_check, void *visibility_ctx);

/**
 * skip_list_get_with_seq_ref
 * zero-copy MVCC get that returns a direct pointer into the version data
 * the returned pointer is only valid while the caller holds a reference
 * to the skip list (e.g. memtable refcount). caller must not free the value.
 * @param list skip list
 * @param key key data
 * @param key_size size of key
 * @param value pointer to const value pointer (do not free)
 * @param value_size pointer to value size
 * @param ttl pointer to ttl
 * @param deleted pointer to deleted flag
 * @param seq pointer to sequence number (output)
 * @param snapshot_seq snapshot sequence number (UINT64_MAX = latest; otherwise the newest version
 *                     with seq <= snapshot_seq, and 0 matches nothing since seqs start at 1)
 * @param visibility_check callback to check if a sequence is committed
 * @param visibility_ctx context for visibility check callback
 * @return 0 on success, -1 on failure
 */
int skip_list_get_with_seq_ref(skip_list_t *list, const uint8_t *key, size_t key_size,
                               const uint8_t **value, size_t *value_size, int64_t *ttl,
                               uint8_t *deleted, uint64_t *seq, uint64_t snapshot_seq,
                               skip_list_visibility_check_fn visibility_check,
                               void *visibility_ctx);

/**
 * skip_list_get_max_seq
 * retrieves only the maximum sequence number for a key without allocating value
 * optimized for conflict detection where only seq comparison is needed
 * @param list skip list
 * @param key key data
 * @param key_size size of key
 * @param out_seq output parameter for sequence number (set to 0 if not found)
 * @return 0 if key found, -1 if not found or error
 */
int skip_list_get_max_seq(skip_list_t *list, const uint8_t *key, size_t key_size,
                          uint64_t *out_seq);

/**
 * skip_list_get_min_seq
 * returns the smallest sequence number ever inserted into the list, or UINT64_MAX if empty.
 * @param list skip list
 * @return smallest inserted seq, or UINT64_MAX when no entry was ever inserted
 */
uint64_t skip_list_get_min_seq(skip_list_t *list);

/**
 * skip_list_cursor_init
 * initializes a new cursor
 * @param cursor pointer to cursor pointer
 * @param list skip list
 * @return 0 on success, -1 on failure
 */
int skip_list_cursor_init(skip_list_cursor_t **cursor, skip_list_t *list);

/**
 * skip_list_cursor_next
 * moves cursor to next entry
 * @param cursor cursor
 * @return 0 on success, -1 on failure
 */
int skip_list_cursor_next(skip_list_cursor_t *cursor);

/**
 * skip_list_cursor_prev
 * moves cursor to previous entry
 * @param cursor cursor
 * @return 0 on success, -1 on failure
 */
int skip_list_cursor_prev(skip_list_cursor_t *cursor);

/**
 * skip_list_cursor_get
 * gets key-value at current cursor position
 * @param cursor cursor
 * @param key pointer to key pointer
 * @param key_size pointer to key size
 * @param value pointer to value pointer
 * @param value_size pointer to value size
 * @param ttl pointer to ttl
 * @param deleted pointer to deleted flag
 * @return 0 on success, -1 on failure
 */
int skip_list_cursor_get(skip_list_cursor_t *cursor, uint8_t **key, size_t *key_size,
                         uint8_t **value, size_t *value_size, int64_t *ttl, uint8_t *deleted);

/**
 * skip_list_cursor_next_get
 * fused next + get in a single call, avoiding redundant sentinel checks
 * and enabling better prefetching. returns zero-copy pointers.
 * @param cursor cursor
 * @param key pointer to key pointer (do not free)
 * @param key_size pointer to key size
 * @param value pointer to value pointer (do not free)
 * @param value_size pointer to value size
 * @param ttl pointer to ttl
 * @param deleted pointer to deleted flag
 * @return 0 on success, -1 on failure (end of list)
 */
int skip_list_cursor_next_get(skip_list_cursor_t *cursor, uint8_t **key, size_t *key_size,
                              uint8_t **value, size_t *value_size, int64_t *ttl, uint8_t *deleted);

/**
 * skip_list_cursor_get_with_seq
 * get key-value pair at cursor position with sequence number
 * @param cursor cursor
 * @param key pointer to key
 * @param key_size pointer to key size
 * @param value pointer to value, NULL when the version's bytes live in the value log
 * @param value_size pointer to value size, the logical length either way
 * @param vlog_id out -- the value log entry holding the value, or 0 when it is inline; may be NULL
 *                only where the caller has established the list holds no references
 * @param ttl pointer to TTL
 * @param deleted out flag carrying the version's SKIP_LIST_FLAG_* bits -- SKIP_LIST_FLAG_DELETED
 *                for a tombstone or expired ttl, OR'd with SKIP_LIST_FLAG_SINGLE_DELETE when set
 * @param seq pointer to sequence number
 * @return 0 on success, -1 on failure
 */
int skip_list_cursor_get_with_seq(skip_list_cursor_t *cursor, uint8_t **key, size_t *key_size,
                                  uint8_t **value, size_t *value_size, uint64_t *vlog_id,
                                  int64_t *ttl, uint8_t *deleted, uint64_t *seq);

/**
 * skip_list_cursor_advance_in_node
 * advance the cursor to the next-older version on the current node without moving
 * to the next key. used by mvcc readers and flushers that need every version still
 * visible to an active snapshot, not just the latest. resets to head on the next
 * cursor seek/next/prev.
 * @param cursor cursor
 * @return 0 on success, -1 when the version chain on the current node is exhausted
 */
int skip_list_cursor_advance_in_node(skip_list_cursor_t *cursor);

/**
 * skip_list_cursor_free
 * frees a cursor
 * @param cursor cursor to free
 */
void skip_list_cursor_free(skip_list_cursor_t *cursor);

/**
 * skip_list_cursor_has_next
 * checks if cursor has next entry
 * @param cursor cursor
 * @return 1 if has next, 0 if not, -1 on error or when positioned at the tail
 */
int skip_list_cursor_has_next(skip_list_cursor_t *cursor);

/**
 * skip_list_cursor_has_prev
 * checks if cursor has previous entry
 * @param cursor cursor
 * @return 1 if has prev, 0 if not, -1 on error or when positioned at the tail
 */
int skip_list_cursor_has_prev(skip_list_cursor_t *cursor);

/**
 * skip_list_cursor_goto_last
 * moves cursor to last entry
 * @param cursor cursor
 * @return 0 on success, -1 on failure
 */
int skip_list_cursor_goto_last(skip_list_cursor_t *cursor);

/**
 * skip_list_cursor_goto_first
 * moves cursor to first entry
 * @param cursor cursor
 * @return 0 on success, -1 on failure
 */
int skip_list_cursor_goto_first(skip_list_cursor_t *cursor);

/**
 * skip_list_cursor_seek
 * positions cursor at the node before the first key >= target
 * @param cursor cursor to position
 * @param key target key
 * @param key_size size of target key
 * @return 0 on success, -1 on failure
 *
 * after calling this function, cursor->current points to the predecessor node.
 * callers must call skip_list_cursor_next() to access the actual first key >= target.
 * this behavior allows efficient insertion and supports both exact matches and range queries.
 */
int skip_list_cursor_seek(skip_list_cursor_t *cursor, const uint8_t *key, size_t key_size);

/**
 * skip_list_cursor_seek_ge
 * seeks cursor directly to the first key >= target, positioning cursor->current on it.
 * unlike skip_list_cursor_seek (which parks on the predecessor and requires a separate
 * skip_list_cursor_next), this folds the advance in and re-reads forward[0] so a concurrent
 * skip_list_put_with_seq that splices a node < target into the predecessor's forward[0] between the
 * descent and the advance cannot leave the cursor on a key below target.
 * @param cursor cursor
 * @param key target key
 * @param key_size size of target key
 * @return 0 if positioned on a key >= target, -1 if no such key exists (cursor at end)
 */
int skip_list_cursor_seek_ge(skip_list_cursor_t *cursor, const uint8_t *key, size_t key_size);

/**
 * skip_list_cursor_seek_for_prev
 * seeks cursor to the last key <= target
 * @param cursor cursor
 * @param key target key
 * @param key_size size of target key
 * @return 0 on success, -1 only on invalid arguments. when no key <= target exists the cursor
 *         parks on the header sentinel and skip_list_cursor_valid then returns 0
 */
int skip_list_cursor_seek_for_prev(skip_list_cursor_t *cursor, const uint8_t *key, size_t key_size);

/**
 * skip_list_cursor_valid
 * checks if cursor is at a valid position (not at sentinel)
 * @param cursor cursor
 * @return 1 if valid, 0 if not, -1 on error
 */
int skip_list_cursor_valid(const skip_list_cursor_t *cursor);

/**
 * skip_list_clear
 * clears all entries from the skip list
 * @param list skip list
 * @return 0 on success, -1 on failure
 */
int skip_list_clear(skip_list_t *list);

/**
 * skip_list_free
 * frees the skip list and all its nodes
 * @param list skip list
 */
void skip_list_free(skip_list_t *list);

/**
 * skip_list_get_data_bytes
 * gets the logical key and value bytes the list holds, which is roughly what flushing it writes
 * @param list skip list
 * @return key and value bytes, 0 when list is NULL
 */
size_t skip_list_get_data_bytes(skip_list_t *list);

/**
 * skip_list_get_memory_bytes
 * gets the memory the list occupies, nodes and pointer arrays and version structs included. this
 * is several times the data bytes at small entry sizes, and it is the figure a memory budget such
 * as the memtable rotation threshold must be compared against
 * @param list skip list
 * @return resident bytes, 0 when list is NULL
 */
size_t skip_list_get_memory_bytes(skip_list_t *list);

/**
 * skip_list_count_entries
 * counts number of entries in skip list
 * @param list skip list
 * @return number of entries, or -1 if list is NULL
 */
int skip_list_count_entries(skip_list_t *list);

/**
 * skip_list_get_min_key
 * gets the minimum key in the skip list
 * @param list skip list
 * @param key pointer to key pointer
 * @param key_size pointer to key size
 * @return 0 on success, -1 on failure
 */
int skip_list_get_min_key(skip_list_t *list, uint8_t **key, size_t *key_size);

/**
 * skip_list_get_max_key
 * gets the maximum key in the skip list
 * @param list skip list
 * @param key pointer to key pointer
 * @param key_size pointer to key size
 * @return 0 on success, -1 on failure
 */
int skip_list_get_max_key(skip_list_t *list, uint8_t **key, size_t *key_size);

#endif /* __SKIP_LIST_H__ */