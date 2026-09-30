/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_TXN_WRITESET_H__
#define __TIDESDB_TXN_WRITESET_H__

#include "../compat.h"
#include "../datastructures/skip_list/skip_list.h" /* the key list a scan walks */
#include "wal_record.h" /* op flag bits (TDB_WAL_ENTRY_TOMBSTONE / SINGLE_DELETE) are shared */

/* a transaction's buffered write set -- the ordered ops it has put or deleted but not yet
 * committed. this is the whole of a txn's uncommitted state (buffer-at-commit: nothing is durable
 * until commit), so it is also the read-your-own-writes source. the ops are kept in insertion
 * order, which is what savepoints and the commit's replay order rest on, and beside them in a skip
 * list over the family-prefixed keys, the order the memtable keeps, with the newest write of each
 * key at the head -- so a lookup reads one head and a scan walks the list, and both cost the same
 * in a transaction of a hundred writes and one of a hundred thousand. the interval deletes, few and
 * covering keys they were never written beside, stay in a short list of their own. every mutation
 * goes through this one guarded api: the owner appends and truncates behind a write lock, and a
 * peer reading the set holds the read lock, so no op-array mutation can race a cross-txn reader.
 * each op's key and value live in a single coalesced allocation (value follows key), so only one
 * pointer is freed per op and a caller can never double-free the value. */

typedef struct tidesdb_writeset tidesdb_writeset_t;

/**
 * tidesdb_writeset_op_t
 * a read-only view of one buffered op, with key and value pointing into the write set
 * @param cf_index the target column family's prefix index
 * @param key the key bytes
 * @param key_size length of key
 * @param value the value bytes, NULL for a tombstone
 * @param value_size length of value, 0 for a tombstone
 * @param ttl absolute expiry time, or -1 for none
 * @param flags op flag bits (TDB_WAL_ENTRY_TOMBSTONE / SINGLE_DELETE)
 */
typedef struct
{
    uint32_t cf_index;
    const uint8_t *key;
    size_t key_size;
    const uint8_t *value;
    size_t value_size;
    int64_t ttl;
    uint8_t flags;
} tidesdb_writeset_op_t;

/**
 * tidesdb_writeset_create
 * create an empty write set
 * @return the write set, or NULL on allocation failure
 */
tidesdb_writeset_t *tidesdb_writeset_create(void);

/**
 * tidesdb_writeset_free
 * free the write set and every op's coalesced buffer
 * @param ws the write set, may be NULL
 */
void tidesdb_writeset_free(tidesdb_writeset_t *ws);

/**
 * tidesdb_writeset_put
 * append a buffered write, copying key and value into one coalesced allocation, under the write
 * lock so a scanning peer sees a consistent op array
 * @param ws the write set
 * @param cf_index the target column family's prefix index
 * @param key the key bytes
 * @param key_size length of key (must be > 0)
 * @param value the value bytes, ignored for a tombstone
 * @param value_size length of value
 * @param ttl absolute expiry time, or -1 for none
 * @param flags op flag bits (0 for a live put, TDB_WAL_ENTRY_TOMBSTONE for a delete)
 * @return TDB_SUCCESS, or TDB_ERR_INVALID_ARGS / TDB_ERR_MEMORY
 */
int tidesdb_writeset_put(tidesdb_writeset_t *ws, uint32_t cf_index, const uint8_t *key,
                         size_t key_size, const uint8_t *value, size_t value_size, int64_t ttl,
                         uint8_t flags);

/**
 * tidesdb_writeset_count
 * the number of buffered ops; an owner-side read, not for use by a cross-txn peer
 * @param ws the write set
 * @return the op count, or 0 if ws is NULL
 */
int tidesdb_writeset_count(const tidesdb_writeset_t *ws);

/**
 * tidesdb_writeset_op_at
 * borrow the op at an index for commit-time serialization or apply; an owner-side read
 * @param ws the write set
 * @param index 0-based op index in insertion order
 * @param out receives the op view
 * @return 1 if the index was in range, 0 otherwise
 */
int tidesdb_writeset_op_at(const tidesdb_writeset_t *ws, int index, tidesdb_writeset_op_t *out);

/**
 * tidesdb_writeset_lookup
 * read-your-own-writes: the latest buffered version of a key under cf_index; an owner-side read, so
 * it takes no lock. the returned view points into the write set and is valid until the next
 * put/truncate
 * @param ws the write set
 * @param cf_index the target column family's prefix index
 * @param key the key bytes
 * @param key_size length of key
 * @param out receives the latest op view covering the key on a hit. a buffered prefix delete covers
 * every key under it, so the view returned for one carries the prefix as its key rather than the
 * key that was asked for -- read its flags and value, not its key
 * @return 1 if the key is buffered (a put, a tombstone, or a prefix delete covering it), 0
 * otherwise
 */
int tidesdb_writeset_lookup(const tidesdb_writeset_t *ws, uint32_t cf_index, const uint8_t *key,
                            size_t key_size, tidesdb_writeset_op_t *out);

/**
 * tidesdb_writeset_keys
 * the key list, for a scan to walk with a cursor: family-prefixed keys, each holding one version
 * per write of it, newest first, whose value is the position of that write. borrowed, valid until
 * the set is freed; the positions it holds are read back through tidesdb_writeset_op_at
 * @param ws the write set
 * @return the key list, or NULL if ws is NULL
 */
skip_list_t *tidesdb_writeset_keys(const tidesdb_writeset_t *ws);

/**
 * tidesdb_writeset_newest
 * the position of the newest point write of a key, what read-your-own-writes and the commit's dedup
 * both resolve a key to; interval deletes are not consulted
 * @param ws the write set
 * @param cf_index the target column family's prefix index
 * @param key the key bytes
 * @param key_size length of key
 * @return the position, or -1 when the key has no point write buffered
 */
int tidesdb_writeset_newest(const tidesdb_writeset_t *ws, uint32_t cf_index, const uint8_t *key,
                            size_t key_size);

/**
 * tidesdb_writeset_covering
 * the position of the newest buffered interval delete of a family that covers a key and was
 * buffered after a given position, so a caller holding the key's own write asks only about the
 * intervals that came after it
 * @param ws the write set
 * @param cf_index the target column family's prefix index
 * @param key the key bytes
 * @param key_size length of key
 * @param after the position an interval must have been buffered after, -1 for any
 * @return the position, or -1 when no such interval is buffered
 */
int tidesdb_writeset_covering(const tidesdb_writeset_t *ws, uint32_t cf_index, const uint8_t *key,
                              size_t key_size, int after);

/**
 * tidesdb_writeset_touches
 * whether the set buffers anything of a family at all, a point write or an interval delete, which
 * is what decides whether a scan of that family needs the set as a source
 * @param ws the write set
 * @param cf_index the target column family's prefix index
 * @return non-zero when it does
 */
int tidesdb_writeset_touches(const tidesdb_writeset_t *ws, uint32_t cf_index);

/**
 * tidesdb_writeset_truncate
 * drop ops back to the first count of them (a savepoint rollback), freeing the rest, under the
 * write lock
 * @param ws the write set
 * @param count the number of ops to keep; clamped to the current count, a negative is treated as 0
 */
int tidesdb_writeset_truncate(tidesdb_writeset_t *ws, int count);

/**
 * tidesdb_writeset_mem_bytes
 * the approximate heap the write set holds (op structs plus coalesced key/value buffers), for the
 * per-txn memory accounting
 * @param ws the write set
 * @return the byte estimate, or 0 if ws is NULL
 */
int64_t tidesdb_writeset_mem_bytes(const tidesdb_writeset_t *ws);

#endif /* __TIDESDB_TXN_WRITESET_H__ */
