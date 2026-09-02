/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_INTERNAL_TYPES_H__
#define __TIDESDB_INTERNAL_TYPES_H__

#include "base/lockfree.h"
#include "compat.h"
#include "datastructures/skip_list/skip_list.h"
#include "io/block_manager.h"
#include "range_tombstone/range_tombstone.h" /* the range tombstones a memtable carries beside its keys */

/* the deadline an entry carries when it never expires; a tombstone is written with it too, since a
 * deleted entry has nothing left to outlive */
#define TDB_TTL_NONE (-1)

/* the entry flags the write path carries from the memtable down into an sstable. only the two
 * tombstone bits travel this way -- the has-ttl and vlog-reference bits are not passed in but
 * derived by btree_builder_add from the ttl and vlog offset it is given, so there is deliberately
 * no constant for them here. these are in-memory bits and not the on-disk flag byte, which is the
 * separate BTREE_ENTRY_FLAG_* set; sstable_builder_emit translates one to the other a bit at a
 * time, so the two are free to disagree numerically. */
#define TDB_KV_FLAG_TOMBSTONE 0x01
#define TDB_KV_FLAG_SINGLE_DELETE                                    \
    0x10 /* tombstone subtype -- the key was put at most once since  \
          * the last single-delete, so put + single-delete drop      \
          * together at a merge that sees both; always set alongside \
          * TDB_KV_FLAG_TOMBSTONE */

/**
 * tidesdb_memtable_t
 * a memtable pairs a skip list with the write-ahead log it recovers from -- the unit that rotates
 * @param skip_list the in-memory sorted structure
 * @param wal the write-ahead log this memtable appends to; a flush worker closes a rotated
 * memtable's wal and clears this while a reader may still hold the active one, so it is atomic
 * @param id unique identifier, matching the backing wal file id
 * @param generation rotation generation counter
 * @param refcount reference count for safe concurrent access
 * @param writers count of commit-path writers actively mutating the wal and skip list
 * @param flushed set once the memtable has been flushed to disk
 * @param claimed set by a flush worker that has taken this immutable to flush while it stays in the
 *                queue and reader-visible, so no other worker claims it and reads see it until it
 * is retired after its data is durable in L1
 * @param vlog_token the value log build token this memtable holds while it references values no
 * sstable names yet, or VLOG_BUILD_TOKEN_NONE. a value a commit separated is reachable only through
 * this memtable until its flush installs, and the segment holding it reads as entirely dead until
 * then, so without a floor covering that segment a reclaim would drain it. taken when the memtable
 * becomes the active one and lowered onto the segment of every reference it goes on to receive --
 * not at the first of them, because a commit writes its value to the value log before it reaches
 * any memtable, and a floor taken only once a reference landed would leave that gap uncovered
 * @param range_tombstones the prefix and range deletes committed into this memtable, over prefixed
 * keys so one set serves every column family, or NULL while none have been. guarded by
 * range_tombstone_lock
 * @param range_tombstone_frags how many fragments that set holds, published so a read can decide to
 * skip the lock entirely -- which is every read of every database that never deletes a range
 * @param range_tombstone_lock guards the set; a commit takes it exclusive and a read takes it
 * shared, and neither reaches it at all while the fragment count reads zero. writer-preferring,
 * because on a family that deletes ranges every read takes it and a commit waiting behind an
 * unbroken run of them would never get in
 */
typedef struct tidesdb_memtable_t
{
    skip_list_t *skip_list;
    _Atomic(block_manager_t *) wal;
    uint64_t id;
    uint64_t generation;
    _Atomic(int) refcount;
    tdb_epoch_t writers;
    _Atomic(int) flushed;
    _Atomic(int) claimed;
    _Atomic(int) vlog_token;
    range_tombstone_set_t *range_tombstones;
    _Atomic(size_t) range_tombstone_frags;
    tdb_wprwlock_t range_tombstone_lock;
} tidesdb_memtable_t;

#endif /* __TIDESDB_INTERNAL_TYPES_H__ */
