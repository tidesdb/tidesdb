/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __RANGE_TOMBSTONE_H__
#define __RANGE_TOMBSTONE_H__
#include "base/errors.h" /* the TDB_SUCCESS and TDB_ERR_* result codes */
#include "compat.h"

/* a range tombstone deletes every key in a half-open interval as of one sequence, so a prefix
 * delete is stored as [prefix, successor(prefix)) and costs one entry however many keys it covers.
 *
 * a set keeps its tombstones fragmented -- split at every endpoint into maximal intervals over
 * which the same tombstones apply, sorted and non-overlapping -- so a query binary searches to one
 * fragment instead of scanning every tombstone. the split happens once per insert, which is the
 * rare direction; reads are the frequent one and pay nothing for it.
 *
 * a fragment carries every sequence covering it, not just the newest, because a read at a snapshot
 * needs the newest sequence at or below that snapshot. collapsing [a,z) at 10 and [c,e) at 20 to a
 * single 20 over [c,e) would hide the still-visible 10 from a read at snapshot 15.
 *
 * a set is single-writer during build and immutable after. concurrent readers are safe against each
 * other; a writer concurrent with anything is not, so a shared set is replaced rather than mutated
 */

/* an upper bound of this length is unbounded above and covers every key from its lower bound on.
 * a bound of zero real bytes cannot mean anything else, since an empty exclusive upper bound would
 * describe an empty interval */
#define RT_UNBOUNDED_ABOVE 0

/* fragments an insert can add beyond splitting each existing one -- the two boundary fragments the
 * new interval cuts in half, plus the run of it that reaches past the last fragment it overlaps */
#define RT_MERGE_SPLIT_HEADROOM 3

/**
 * rt_fragment_t
 * one maximal interval over which the same set of range tombstones applies, half-open as [lo, hi)
 * @param lo inclusive lower bound owned by the fragment, of zero length when it starts at the first
 *           key the order admits
 * @param lo_size length of lo in bytes
 * @param hi exclusive upper bound owned by the fragment, NULL when the fragment is unbounded above
 * @param hi_size length of hi in bytes, RT_UNBOUNDED_ABOVE when the fragment is unbounded above
 * @param seqs the sequences of every tombstone covering this interval, sorted descending and owned
 *             by the fragment
 * @param seq_count how many sequences cover it, never zero for a fragment held by a set
 */
typedef struct
{
    uint8_t *lo;
    size_t lo_size;
    uint8_t *hi;
    size_t hi_size;
    uint64_t *seqs;
    size_t seq_count;
} rt_fragment_t;

/**
 * range_tombstone_set_t
 * a fragmented set of range tombstones, sorted by lower bound and non-overlapping
 * @param frags the fragments in ascending key order, NULL while the set is empty
 * @param count how many fragments the set holds
 * @param capacity how many the frags array can hold before it has to grow
 */
typedef struct
{
    rt_fragment_t *frags;
    size_t count;
    size_t capacity;
} range_tombstone_set_t;

/**
 * range_tombstone_set_new
 * allocate an empty set, which covers no key at any sequence
 * @return the set, or NULL when the allocation fails
 */
range_tombstone_set_t *range_tombstone_set_new(void);

/**
 * range_tombstone_set_free
 * release a set and every fragment in it
 * @param set the set to free, or NULL
 */
void range_tombstone_set_free(range_tombstone_set_t *set);

/**
 * range_tombstone_set_add
 * add the tombstone [lo, hi) at seq and re-fragment around it, leaving the set sorted and
 * non-overlapping. the set is rebuilt into fresh storage and swapped in, so it is unchanged when
 * the call fails
 * @param set the set to add to
 * @param lo inclusive lower bound, which may be of zero length to start at the first key
 * @param lo_size length of lo in bytes
 * @param hi exclusive upper bound, or NULL with hi_size RT_UNBOUNDED_ABOVE for unbounded above
 * @param hi_size length of hi in bytes, or RT_UNBOUNDED_ABOVE for unbounded above
 * @param seq the sequence the tombstone was written at
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS when the set is NULL or the interval is empty, or
 *         TDB_ERR_MEMORY
 */
int range_tombstone_set_add(range_tombstone_set_t *set, const uint8_t *lo, size_t lo_size,
                            const uint8_t *hi, size_t hi_size, uint64_t seq);

/**
 * range_tombstone_max_covering
 * the newest sequence at or below snapshot_seq whose tombstone covers key -- what a read compares
 * against the key's own newest visible version to decide whether the key is deleted
 * @param set the set to query, which may be empty
 * @param key the key to test
 * @param key_size length of key in bytes
 * @param snapshot_seq the ceiling a read is looking below, inclusive
 * @param out_seq set to the covering sequence when the call returns 1, untouched otherwise
 * @return 1 when a tombstone at or below snapshot_seq covers the key, 0 when none does, or
 *         TDB_ERR_INVALID_ARGS when set, key or out_seq is NULL
 */
int range_tombstone_max_covering(const range_tombstone_set_t *set, const uint8_t *key,
                                 size_t key_size, uint64_t snapshot_seq, uint64_t *out_seq);

/**
 * range_tombstone_covering_fragment
 * borrow the fragment covering a key, with every sequence it carries -- for a reader that has to
 * filter those sequences itself rather than simply take the newest below a ceiling, which is what
 * skipping an abandoned commit's sequence needs. the fragment belongs to the set and is valid until
 * the set is changed or freed
 * @param set the set to query, which may be empty
 * @param key the key to test
 * @param key_size length of key in bytes
 * @param out set to the covering fragment when the call returns 1, untouched otherwise
 * @return 1 when a fragment covers the key, 0 when none does, or TDB_ERR_INVALID_ARGS when set, key
 *         or out is NULL
 */
int range_tombstone_covering_fragment(const range_tombstone_set_t *set, const uint8_t *key,
                                      size_t key_size, const rt_fragment_t **out);

/**
 * range_tombstone_set_count
 * how many fragments the set holds, which is what a builder writes and what a reader binary
 * searches, not the number of tombstones added
 * @param set the set to measure, or NULL
 * @return the fragment count, or 0 when set is NULL
 */
size_t range_tombstone_set_count(const range_tombstone_set_t *set);

/**
 * range_tombstone_set_fragment_at
 * borrow one fragment by position, for a builder writing the set out or a test inspecting it. the
 * fragment belongs to the set and is valid until the set is changed or freed
 * @param set the set to read from
 * @param i the position, from 0 to the fragment count
 * @param out set to the fragment on success, untouched otherwise
 * @return TDB_SUCCESS, or TDB_ERR_INVALID_ARGS when set or out is NULL or i is out of range
 */
int range_tombstone_set_fragment_at(const range_tombstone_set_t *set, size_t i,
                                    const rt_fragment_t **out);

/**
 * range_tombstone_set_bytes
 * roughly what the set costs in memory, so a memtable holding nothing but range deletes still
 * measures as holding something and rotates on size like any other
 * @param set the set to measure, or NULL
 * @return the byte count, or 0 when set is NULL
 */
size_t range_tombstone_set_bytes(const range_tombstone_set_t *set);

/**
 * range_tombstone_set_clone
 * deep copy a set, so a writer can build the next version while readers keep using this one
 * @param set the set to copy
 * @return the copy, or NULL when set is NULL or an allocation fails
 */
range_tombstone_set_t *range_tombstone_set_clone(const range_tombstone_set_t *set);

/* on-disk version of a serialized set, checked on the way back in so a block written by a build
 * this one does not speak is refused rather than read as fragments */
#define RT_BLOCK_VERSION 1

/* the smallest a serialized fragment can be -- a zero-length lower bound, an unbounded upper bound
 * and one sequence. it is what bounds the fragment count a block may claim against its own length,
 * so a malformed count cannot ask for an allocation the bytes could never fill */
#define RT_BLOCK_MIN_FRAGMENT_BYTES (3 * sizeof(uint32_t) + sizeof(uint64_t))

/**
 * range_tombstone_set_serialize
 * write a set out as one self-describing block, for an sstable to carry beside its keys
 * @param set the set to serialize, which may be empty
 * @param out receives the owned buffer the caller frees
 * @param out_size receives the buffer length
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, or TDB_ERR_MEMORY
 */
int range_tombstone_set_serialize(const range_tombstone_set_t *set, uint8_t **out,
                                  size_t *out_size);

/**
 * range_tombstone_set_deserialize
 * rebuild a set from a serialized block, validating every count and length against what the buffer
 * actually holds rather than trusting the block
 * @param data the serialized bytes
 * @param size length of data
 * @param out receives the rebuilt set, owned by the caller
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_MEMORY, or TDB_ERR_CORRUPTION on a block whose
 *         version, counts or lengths its own bytes cannot support
 */
int range_tombstone_set_deserialize(const uint8_t *data, size_t size, range_tombstone_set_t **out);

/**
 * range_tombstone_prefix_successor
 * the exclusive upper bound of the interval covering every key starting with prefix -- the prefix
 * with its trailing 0xff bytes stripped and the last byte left incremented. a prefix of nothing but
 * 0xff bytes has no successor in the order and is unbounded above instead
 * @param prefix the prefix to bound, which may be of zero length
 * @param prefix_size length of prefix in bytes
 * @param out_hi set to the owned upper bound the caller frees, or NULL when unbounded above
 * @param out_hi_size set to the length of out_hi, or RT_UNBOUNDED_ABOVE when unbounded above
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS when out_hi or out_hi_size is NULL, or TDB_ERR_MEMORY
 */
int range_tombstone_prefix_successor(const uint8_t *prefix, size_t prefix_size, uint8_t **out_hi,
                                     size_t *out_hi_size);

/**
 * range_tombstone_interval_valid
 * whether an interval is one a tombstone set can hold, which is one covering at least one key
 *
 * the rule lives here, and a caller that must refuse a bad interval earlier than the set would meet
 * it asks rather than restating it, so the two cannot come to disagree about what an interval is
 * @param lo inclusive lower bound
 * @param lo_size length of lo in bytes
 * @param hi exclusive upper bound, or NULL with hi_size RT_UNBOUNDED_ABOVE for unbounded above
 * @param hi_size length of hi in bytes, RT_UNBOUNDED_ABOVE when unbounded above
 * @return 1 when the interval covers at least one key, 0 otherwise
 */
int range_tombstone_interval_valid(const uint8_t *lo, size_t lo_size, const uint8_t *hi,
                                   size_t hi_size);

#endif /* __RANGE_TOMBSTONE_H__ */
