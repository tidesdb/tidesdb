/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_BASE_KEYCMP_H__
#define __TIDESDB_BASE_KEYCMP_H__

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* the engine orders keys one way and one way only -- byte-wise, with the shorter key first when one
 * is a prefix of the other. every structure that sorts or searches keys shares this: the memtable's
 * skip list, the klog btree, the partition filter, the level set's bounds, the merge iterator, the
 * compaction planner's boundaries, the interval tombstones, and the transaction write and read
 * sets. written once here so those cannot drift apart, since two of them disagreeing would not
 * fail a build or a test -- it would place a key on the wrong side of a bound and lose it. */

/**
 * tdb_key_cmp
 * order two keys byte-wise, breaking a tie on the shared prefix by the shorter key
 * @param a the first key, which may be NULL when a_size is zero
 * @param a_size length of a in bytes
 * @param b the second key, which may be NULL when b_size is zero
 * @param b_size length of b in bytes
 * @return -1 when a sorts before b, 1 when after, 0 when they are the same key
 */
static inline int tdb_key_cmp(const uint8_t *a, const size_t a_size, const uint8_t *b,
                              const size_t b_size)
{
    const size_t min_size = a_size < b_size ? a_size : b_size;
    /* a zero length is a real key here -- an sstable carrying nothing but an interval tombstone has
     * no key to name itself with -- and memcmp requires valid pointers whatever the count it is
     * given, so the empty case never reaches it */
    const int c = min_size > 0 ? memcmp(a, b, min_size) : 0;
    if (c != 0) return c < 0 ? -1 : 1;
    if (a_size < b_size) return -1;
    if (a_size > b_size) return 1;
    return 0;
}

#endif /* __TIDESDB_BASE_KEYCMP_H__ */
