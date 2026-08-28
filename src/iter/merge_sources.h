/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_MERGE_SOURCES_H__
#define __TIDESDB_MERGE_SOURCES_H__

#include "datastructures/skip_list/skip_list.h"
#include "memtable/memtable.h" /* the memtable a view reads, for the intervals it holds */
#include "merge_iter.h"
#include "sstable/sstable.h"

/* merge_sources adapts the two concrete cursors -- an sstable_iter and a skip_list cursor over the
 * shared memtable -- into the merge_iter source interface. the sstable adapter is a thin
 * pass-through since an sstable already stores one column family's unprefixed keys with all
 * versions. the memtable adapter is a view of one column family inside the shared skip_list: it
 * strips the 4-byte cf-index prefix, stays within that family's key range, and resolves each key to
 * its newest version at or below the snapshot, so it yields at most one entry per key and reads
 * cleanly in both directions. */

/**
 * sstable_merge_source
 * fill a merge source that reads an sstable through its bidirectional cursor; the sstable already
 * holds one family's unprefixed keys with every version, so the merge resolves the snapshot over
 * them
 * @param it the sstable cursor to wrap, borrowed and positioned by the merge
 * @param out the source to fill
 */
void sstable_merge_source(sstable_iter_t *it, merge_source_t *out);

/**
 * memtable_merge_source_t
 * the state a memtable view keeps between calls -- the borrowed skip_list cursor, the column family
 * it filters to, the snapshot it resolves at, and the currently resolved entry
 * @param cursor the borrowed skip_list cursor over the shared memtable
 * @param cf_index the column family whose prefix range this view iterates
 * @param snapshot the snapshot sequence versions are resolved at
 * @param positioned 1 when resolved on a visible in-range entry
 * @param key the resolved entry's unprefixed key, pointing into the skip_list node
 * @param key_size length of key
 * @param value the resolved version's value, pointing into the skip_list version, NULL when the
 * bytes live in the value log
 * @param value_size the value's logical length either way
 * @param vlog_id the value log entry holding the value, or 0 when it is inline
 * @param seq the resolved version's sequence
 * @param ttl the resolved version's expiry
 * @param deleted non-zero when the resolved version is a tombstone
 */
/* stack room for the prefixed form of a key while a memtable view is asked about its intervals */
#define MERGE_SOURCE_PREFIXED_KEY_STACK 128

typedef struct
{
    skip_list_cursor_t *cursor;
    /* the memtable this view reads and the subsystem that owns it, so the view can be asked about
     * the intervals the memtable holds as well as the keys */
    tidesdb_l0_t *l0;
    tidesdb_memtable_t *mt;
    uint32_t cf_index;
    uint64_t snapshot;
    int positioned;
    const uint8_t *key;
    size_t key_size;
    const uint8_t *value;
    size_t value_size;
    uint64_t vlog_id;
    uint64_t seq;
    int64_t ttl;
    uint8_t deleted;
} memtable_merge_source_t;

/**
 * memtable_merge_source_init
 * initialize a memtable view over a borrowed cursor for one column family at a snapshot
 * @param s the view state to initialize
 * @param cursor the borrowed skip_list cursor
 * @param cf_index the column family to filter to
 * @param snapshot the snapshot sequence to resolve at
 */
void memtable_merge_source_init(memtable_merge_source_t *s, skip_list_cursor_t *cursor,
                                tidesdb_l0_t *l0, tidesdb_memtable_t *mt, uint32_t cf_index,
                                uint64_t snapshot);

/**
 * memtable_merge_source
 * fill a merge source backed by an initialized memtable view
 * @param s the initialized view state, borrowed
 * @param out the source to fill
 */
void memtable_merge_source(memtable_merge_source_t *s, merge_source_t *out);

/* a transaction's buffered write set, forward-declared so this header does not pull in the txn
 * layer; the writeset overlay adapter reads it through the public writeset api in the source file
 */
typedef struct tidesdb_writeset tidesdb_writeset_t;

/**
 * writeset_merge_source_t
 * a read-your-own-writes overlay over one transaction's buffered puts and deletes for a column
 * family, so a scan inside the transaction sees its own uncommitted rows; opaque, owning a sorted
 * latest-per-key snapshot taken at creation
 */
typedef struct writeset_merge_source writeset_merge_source_t;

/**
 * writeset_merge_source_new
 * snapshot a transaction's buffered ops for one column family into a sorted, latest-per-key overlay
 * source; every entry reports seq so the merge lets it win over any committed version at or below
 * that snapshot. borrows the write set's key and value buffers, so the source must not outlive them
 * @param ws the transaction's write set
 * @param cf_index the column family whose ops to overlay
 * @param seq the sequence every overlay entry reports, the transaction's read snapshot
 * @return the overlay source, or NULL on allocation failure or when the write set has no ops for
 * the column family (the caller then folds no overlay)
 */
writeset_merge_source_t *writeset_merge_source_new(const tidesdb_writeset_t *ws, uint32_t cf_index,
                                                   uint64_t seq);

/**
 * writeset_merge_source
 * fill a merge source backed by a writeset overlay handle
 * @param s the overlay handle, borrowed
 * @param out the source to fill
 */
void writeset_merge_source(writeset_merge_source_t *s, merge_source_t *out);

/**
 * writeset_merge_source_free
 * free a writeset overlay handle and its snapshot; safe on NULL
 * @param s the overlay handle, may be NULL
 */
void writeset_merge_source_free(writeset_merge_source_t *s);

#endif /* __TIDESDB_MERGE_SOURCES_H__ */
