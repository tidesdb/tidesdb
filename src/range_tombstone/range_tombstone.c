/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "range_tombstone/range_tombstone.h"

#include <stdlib.h>
#include <string.h>

#include "base/encoding/serialization.h" /* the big-endian fixed-width codec the block is written in */

/* the largest value a key byte can hold, which is what a prefix has to be stripped of before its
 * successor can be formed by incrementing */
#define RT_KEY_BYTE_MAX 0xff

/* fragments the first append reserves room for, doubled from there. a set built by appending is
 * one being rebuilt from a source that already knows its own shape, so it grows once or twice */
#define RT_APPEND_INITIAL_CAPACITY 8

/**
 * rt_key_cmp
 * total byte-wise order over keys -- the shared prefix decides, otherwise the shorter key sorts
 * first, matching the order the memtable and the sstables are already sorted in
 * @param key1 first key
 * @param key1_size size of the first key in bytes
 * @param key2 second key
 * @param key2_size size of the second key in bytes
 * @return negative if key1 < key2, 0 if equal, positive if key1 > key2
 */
static int rt_key_cmp(const uint8_t *key1, const size_t key1_size, const uint8_t *key2,
                      const size_t key2_size)
{
    const size_t min_size = key1_size < key2_size ? key1_size : key2_size;
    const int c = min_size > 0 ? memcmp(key1, key2, min_size) : 0;
    if (c != 0) return c < 0 ? -1 : 1;
    if (key1_size < key2_size) return -1;
    if (key1_size > key2_size) return 1;
    return 0;
}

/**
 * rt_hi_cmp_key
 * order an exclusive upper bound against a key, with an unbounded bound sorting after every key
 * @param hi the upper bound, NULL when unbounded above
 * @param hi_size length of hi in bytes, RT_UNBOUNDED_ABOVE when unbounded above
 * @param key the key to order it against
 * @param key_size length of key in bytes
 * @return negative if hi < key, 0 if equal, positive if hi > key
 */
static int rt_hi_cmp_key(const uint8_t *hi, const size_t hi_size, const uint8_t *key,
                         const size_t key_size)
{
    if (hi_size == RT_UNBOUNDED_ABOVE) return 1;
    return rt_key_cmp(hi, hi_size, key, key_size);
}

/**
 * rt_hi_cmp_hi
 * order two exclusive upper bounds, either of which may be unbounded above
 * @param a first upper bound
 * @param a_size length of a in bytes, RT_UNBOUNDED_ABOVE when unbounded above
 * @param b second upper bound
 * @param b_size length of b in bytes, RT_UNBOUNDED_ABOVE when unbounded above
 * @return negative if a < b, 0 if equal, positive if a > b
 */
static int rt_hi_cmp_hi(const uint8_t *a, const size_t a_size, const uint8_t *b,
                        const size_t b_size)
{
    if (a_size == RT_UNBOUNDED_ABOVE && b_size == RT_UNBOUNDED_ABOVE) return 0;
    if (a_size == RT_UNBOUNDED_ABOVE) return 1;
    if (b_size == RT_UNBOUNDED_ABOVE) return -1;
    return rt_key_cmp(a, a_size, b, b_size);
}

/**
 * rt_frag_free
 * release a fragment's bounds and sequences and leave it empty, so a partially built set can be
 * unwound one fragment at a time
 * @param frag the fragment to release, or NULL
 */
static void rt_frag_free(rt_fragment_t *frag)
{
    if (!frag) return;
    free(frag->lo);
    free(frag->hi);
    free(frag->seqs);
    frag->lo = NULL;
    frag->hi = NULL;
    frag->seqs = NULL;
    frag->lo_size = 0;
    frag->hi_size = RT_UNBOUNDED_ABOVE;
    frag->seq_count = 0;
}

/**
 * rt_emit
 * append one fragment to a set being built, copying the bounds and the sequences covering it and
 * folding in one more sequence where the caller is adding a tombstone over the interval
 * @param out the set being built, pre-sized by the caller to hold the append
 * @param lo inclusive lower bound to copy
 * @param lo_size length of lo in bytes
 * @param hi exclusive upper bound to copy, NULL when unbounded above
 * @param hi_size length of hi in bytes, RT_UNBOUNDED_ABOVE when unbounded above
 * @param seqs the sequences to copy in descending order, or NULL for none
 * @param seq_count how many sequences to copy
 * @param extra one further sequence to merge into them, or NULL to copy them unchanged
 * @return TDB_SUCCESS, TDB_ERR_MEMORY, or TDB_ERR_INVALID_ARGS when out has no room left
 */
static int rt_emit(range_tombstone_set_t *out, const uint8_t *lo, const size_t lo_size,
                   const uint8_t *hi, const size_t hi_size, const uint64_t *seqs,
                   const size_t seq_count, const uint64_t *extra)
{
    if (out->count >= out->capacity) return TDB_ERR_INVALID_ARGS;

    rt_fragment_t *frag = &out->frags[out->count];
    frag->lo = NULL;
    frag->hi = NULL;
    frag->seqs = NULL;
    frag->lo_size = lo_size;
    frag->hi_size = hi_size;
    frag->seq_count = 0;

    if (lo_size > 0)
    {
        frag->lo = malloc(lo_size);
        if (!frag->lo)
        {
            rt_frag_free(frag);
            return TDB_ERR_MEMORY;
        }
        memcpy(frag->lo, lo, lo_size);
    }

    if (hi_size > RT_UNBOUNDED_ABOVE)
    {
        frag->hi = malloc(hi_size);
        if (!frag->hi)
        {
            rt_frag_free(frag);
            return TDB_ERR_MEMORY;
        }
        memcpy(frag->hi, hi, hi_size);
    }

    frag->seqs = malloc((seq_count + 1) * sizeof(uint64_t));
    if (!frag->seqs)
    {
        rt_frag_free(frag);
        return TDB_ERR_MEMORY;
    }

    /* the sequences stay sorted descending so a snapshot read takes the first one at or below its
     * ceiling and stops. a sequence already present is not repeated, which is what two tombstones
     * committed together over overlapping intervals would otherwise produce */
    size_t n = 0;
    int placed = extra ? 0 : 1;
    for (size_t i = 0; i < seq_count; i++)
    {
        if (!placed && *extra > seqs[i])
        {
            frag->seqs[n++] = *extra;
            placed = 1;
        }
        if (!placed && *extra == seqs[i]) placed = 1;
        frag->seqs[n++] = seqs[i];
    }
    if (!placed) frag->seqs[n++] = *extra;

    frag->seq_count = n;
    out->count++;
    return TDB_SUCCESS;
}

/**
 * rt_copy_frag
 * append an existing fragment to a set being built, bounds and sequences unchanged
 * @param out the set being built
 * @param frag the fragment to copy
 * @return TDB_SUCCESS, TDB_ERR_MEMORY, or TDB_ERR_INVALID_ARGS when out has no room left
 */
static int rt_copy_frag(range_tombstone_set_t *out, const rt_fragment_t *frag)
{
    return rt_emit(out, frag->lo, frag->lo_size, frag->hi, frag->hi_size, frag->seqs,
                   frag->seq_count, NULL);
}

/**
 * rt_merge
 * build the fragmentation of a set with one more tombstone laid over it -- fragments the new
 * interval misses are copied, fragments it reaches are split at its bounds with the overlap gaining
 * its sequence, and the runs of it that fall between fragments become fragments of their own
 * @param set the fragmented set to lay the tombstone over
 * @param lo inclusive lower bound of the new tombstone
 * @param lo_size length of lo in bytes
 * @param hi exclusive upper bound of the new tombstone, NULL when unbounded above
 * @param hi_size length of hi in bytes, RT_UNBOUNDED_ABOVE when unbounded above
 * @param seq the sequence the new tombstone was written at
 * @param out the set to build into, pre-sized to hold every fragment the merge can produce
 * @return TDB_SUCCESS, TDB_ERR_MEMORY, or TDB_ERR_INVALID_ARGS when out was sized too small
 */
static int rt_merge(const range_tombstone_set_t *set, const uint8_t *lo, const size_t lo_size,
                    const uint8_t *hi, const size_t hi_size, const uint64_t seq,
                    range_tombstone_set_t *out)
{
    const uint8_t *pos = lo;
    size_t pos_size = lo_size;
    size_t i = 0;
    int rc = TDB_SUCCESS;
    int reached_end = 0;

    /* fragments ending at or before the new interval starts are untouched by it */
    while (i < set->count &&
           rt_hi_cmp_key(set->frags[i].hi, set->frags[i].hi_size, lo, lo_size) <= 0)
    {
        rc = rt_copy_frag(out, &set->frags[i]);
        if (rc != TDB_SUCCESS) return rc;
        i++;
    }

    while (!reached_end && i < set->count &&
           rt_hi_cmp_key(hi, hi_size, set->frags[i].lo, set->frags[i].lo_size) > 0)
    {
        const rt_fragment_t *frag = &set->frags[i];
        const uint8_t *ov_hi = hi;
        size_t ov_hi_size = hi_size;

        /* the run of the new interval reaching this fragment carries only its own sequence */
        if (rt_key_cmp(pos, pos_size, frag->lo, frag->lo_size) < 0)
        {
            rc = rt_emit(out, pos, pos_size, frag->lo, frag->lo_size, NULL, 0, &seq);
            if (rc != TDB_SUCCESS) return rc;
            pos = frag->lo;
            pos_size = frag->lo_size;
        }

        /* the head of a fragment the new interval starts inside keeps only what already covered it
         */
        if (rt_key_cmp(frag->lo, frag->lo_size, pos, pos_size) < 0)
        {
            rc = rt_emit(out, frag->lo, frag->lo_size, pos, pos_size, frag->seqs, frag->seq_count,
                         NULL);
            if (rc != TDB_SUCCESS) return rc;
        }

        if (rt_hi_cmp_hi(frag->hi, frag->hi_size, hi, hi_size) < 0)
        {
            ov_hi = frag->hi;
            ov_hi_size = frag->hi_size;
        }

        rc = rt_emit(out, pos, pos_size, ov_hi, ov_hi_size, frag->seqs, frag->seq_count, &seq);
        if (rc != TDB_SUCCESS) return rc;
        pos = ov_hi;
        pos_size = ov_hi_size;

        /* both bounds unbounded is the one case where nothing can follow, and where pos has run off
         * the end of the order and must not be compared against anything again */
        if (ov_hi_size == RT_UNBOUNDED_ABOVE) reached_end = 1;

        /* the tail of a fragment reaching past the new interval keeps only what already covered it
         */
        if (rt_hi_cmp_hi(frag->hi, frag->hi_size, ov_hi, ov_hi_size) > 0)
        {
            rc = rt_emit(out, ov_hi, ov_hi_size, frag->hi, frag->hi_size, frag->seqs,
                         frag->seq_count, NULL);
            if (rc != TDB_SUCCESS) return rc;
        }
        i++;
    }

    /* the run of the new interval past every fragment it reached carries only its own sequence */
    if (!reached_end && rt_hi_cmp_key(hi, hi_size, pos, pos_size) > 0)
    {
        rc = rt_emit(out, pos, pos_size, hi, hi_size, NULL, 0, &seq);
        if (rc != TDB_SUCCESS) return rc;
    }

    while (i < set->count)
    {
        rc = rt_copy_frag(out, &set->frags[i]);
        if (rc != TDB_SUCCESS) return rc;
        i++;
    }
    return TDB_SUCCESS;
}

/**
 * rt_starts_after_last
 * whether a lower bound begins at or after the end of the set's last fragment, which is what keeps
 * the fragments sorted and non-overlapping as they are read back
 * @param set the set built so far
 * @param lo the lower bound to place
 * @param lo_size length of lo in bytes
 * @return 1 when the bound may start a fragment after the last one, 0 otherwise
 */
static int rt_starts_after_last(const range_tombstone_set_t *set, const uint8_t *lo,
                                const size_t lo_size)
{
    if (set->count == 0) return 1;

    /* nothing can follow a fragment that reaches the end of the order */
    const rt_fragment_t *prev = &set->frags[set->count - 1];
    if (prev->hi_size == RT_UNBOUNDED_ABOVE) return 0;
    return rt_hi_cmp_key(prev->hi, prev->hi_size, lo, lo_size) <= 0;
}

range_tombstone_set_t *range_tombstone_set_new(void)
{
    return calloc(1, sizeof(range_tombstone_set_t));
}

void range_tombstone_set_free(range_tombstone_set_t *set)
{
    if (!set) return;
    for (size_t i = 0; i < set->count; i++) rt_frag_free(&set->frags[i]);
    free(set->frags);
    free(set);
}

int range_tombstone_interval_valid(const uint8_t *lo, const size_t lo_size, const uint8_t *hi,
                                   const size_t hi_size)
{
    if (lo_size > 0 && !lo) return 0;
    if (hi_size > RT_UNBOUNDED_ABOVE && !hi) return 0;

    /* an interval ending at or before it starts covers no key, and would fragment into nothing */
    return rt_hi_cmp_key(hi, hi_size, lo, lo_size) > 0;
}

int range_tombstone_set_add(range_tombstone_set_t *set, const uint8_t *lo, const size_t lo_size,
                            const uint8_t *hi, const size_t hi_size, const uint64_t seq)
{
    if (!set) return TDB_ERR_INVALID_ARGS;
    if (!range_tombstone_interval_valid(lo, lo_size, hi, hi_size)) return TDB_ERR_INVALID_ARGS;

    range_tombstone_set_t out;
    out.count = 0;
    out.capacity = set->count * 2 + RT_MERGE_SPLIT_HEADROOM;
    out.frags = calloc(out.capacity, sizeof(rt_fragment_t));
    if (!out.frags) return TDB_ERR_MEMORY;

    const int rc = rt_merge(set, lo, lo_size, hi, hi_size, seq, &out);
    if (rc != TDB_SUCCESS)
    {
        for (size_t i = 0; i < out.count; i++) rt_frag_free(&out.frags[i]);
        free(out.frags);
        return rc;
    }

    for (size_t i = 0; i < set->count; i++) rt_frag_free(&set->frags[i]);
    free(set->frags);
    set->frags = out.frags;
    set->count = out.count;
    set->capacity = out.capacity;
    return TDB_SUCCESS;
}

int range_tombstone_set_append_fragment(range_tombstone_set_t *set, const uint8_t *lo,
                                        const size_t lo_size, const uint8_t *hi,
                                        const size_t hi_size, const uint64_t *seqs,
                                        const size_t seq_count)
{
    if (!set || !seqs || seq_count == 0) return TDB_ERR_INVALID_ARGS;
    if (!range_tombstone_interval_valid(lo, lo_size, hi, hi_size)) return TDB_ERR_INVALID_ARGS;
    if (!rt_starts_after_last(set, lo, lo_size)) return TDB_ERR_INVALID_ARGS;

    /* strictly descending is what lets a snapshot read take the first sequence at or below its
     * ceiling and stop */
    for (size_t i = 1; i < seq_count; i++)
        if (seqs[i] >= seqs[i - 1]) return TDB_ERR_INVALID_ARGS;

    if (set->count == set->capacity)
    {
        const size_t grown = set->capacity ? set->capacity * 2 : RT_APPEND_INITIAL_CAPACITY;
        rt_fragment_t *frags = realloc(set->frags, grown * sizeof(rt_fragment_t));
        if (!frags) return TDB_ERR_MEMORY;
        set->frags = frags;
        set->capacity = grown;
    }
    return rt_emit(set, lo, lo_size, hi, hi_size, seqs, seq_count, NULL);
}

int range_tombstone_covering_fragment(const range_tombstone_set_t *set, const uint8_t *key,
                                      const size_t key_size, const rt_fragment_t **out)
{
    if (!set || !key || !out) return TDB_ERR_INVALID_ARGS;
    if (set->count == 0) return 0;

    /* fragments are sorted and never overlap, so the last one starting at or below the key is the
     * only one that can cover it */
    size_t lo_i = 0;
    size_t hi_i = set->count;
    while (lo_i < hi_i)
    {
        const size_t mid = lo_i + (hi_i - lo_i) / 2;
        if (rt_key_cmp(set->frags[mid].lo, set->frags[mid].lo_size, key, key_size) <= 0)
            lo_i = mid + 1;
        else
            hi_i = mid;
    }
    if (lo_i == 0) return 0;

    const rt_fragment_t *frag = &set->frags[lo_i - 1];
    if (rt_hi_cmp_key(frag->hi, frag->hi_size, key, key_size) <= 0) return 0;

    *out = frag;
    return 1;
}

int range_tombstone_max_covering(const range_tombstone_set_t *set, const uint8_t *key,
                                 const size_t key_size, const uint64_t snapshot_seq,
                                 uint64_t *out_seq)
{
    if (!out_seq) return TDB_ERR_INVALID_ARGS;

    const rt_fragment_t *frag = NULL;
    const int covered = range_tombstone_covering_fragment(set, key, key_size, &frag);
    if (covered != 1) return covered;

    for (size_t i = 0; i < frag->seq_count; i++)
    {
        if (frag->seqs[i] <= snapshot_seq)
        {
            *out_seq = frag->seqs[i];
            return 1;
        }
    }
    return 0;
}

size_t range_tombstone_set_count(const range_tombstone_set_t *set)
{
    return set ? set->count : 0;
}

size_t range_tombstone_set_bytes(const range_tombstone_set_t *set)
{
    if (!set) return 0;

    size_t total = set->capacity * sizeof(rt_fragment_t);
    for (size_t i = 0; i < set->count; i++)
        total += set->frags[i].lo_size + set->frags[i].hi_size +
                 set->frags[i].seq_count * sizeof(uint64_t);
    return total;
}

int range_tombstone_set_fragment_at(const range_tombstone_set_t *set, const size_t i,
                                    const rt_fragment_t **out)
{
    if (!set || !out || i >= set->count) return TDB_ERR_INVALID_ARGS;
    *out = &set->frags[i];
    return TDB_SUCCESS;
}

range_tombstone_set_t *range_tombstone_set_clone(const range_tombstone_set_t *set)
{
    if (!set) return NULL;

    range_tombstone_set_t *copy = calloc(1, sizeof(range_tombstone_set_t));
    if (!copy) return NULL;
    if (set->count == 0) return copy;

    copy->frags = calloc(set->count, sizeof(rt_fragment_t));
    if (!copy->frags)
    {
        free(copy);
        return NULL;
    }
    copy->capacity = set->count;

    for (size_t i = 0; i < set->count; i++)
    {
        if (rt_copy_frag(copy, &set->frags[i]) != TDB_SUCCESS)
        {
            range_tombstone_set_free(copy);
            return NULL;
        }
    }
    return copy;
}

int range_tombstone_set_serialize(const range_tombstone_set_t *set, uint8_t **out, size_t *out_size)
{
    if (!set || !out || !out_size) return TDB_ERR_INVALID_ARGS;

    size_t total = sizeof(uint8_t) + sizeof(uint32_t);
    for (size_t i = 0; i < set->count; i++)
        total += 3 * sizeof(uint32_t) + set->frags[i].lo_size + set->frags[i].hi_size +
                 set->frags[i].seq_count * sizeof(uint64_t);

    uint8_t *buf = malloc(total);
    if (!buf) return TDB_ERR_MEMORY;

    uint8_t *p = buf;
    *p++ = RT_BLOCK_VERSION;
    tdb_encode_be32((uint32_t)set->count, p);
    p += sizeof(uint32_t);

    for (size_t i = 0; i < set->count; i++)
    {
        const rt_fragment_t *frag = &set->frags[i];
        tdb_encode_be32((uint32_t)frag->lo_size, p);
        p += sizeof(uint32_t);
        if (frag->lo_size)
        {
            memcpy(p, frag->lo, frag->lo_size);
            p += frag->lo_size;
        }
        tdb_encode_be32((uint32_t)frag->hi_size, p);
        p += sizeof(uint32_t);
        if (frag->hi_size)
        {
            memcpy(p, frag->hi, frag->hi_size);
            p += frag->hi_size;
        }
        tdb_encode_be32((uint32_t)frag->seq_count, p);
        p += sizeof(uint32_t);
        for (size_t s = 0; s < frag->seq_count; s++)
        {
            tdb_encode_be64(frag->seqs[s], p);
            p += sizeof(uint64_t);
        }
    }

    *out = buf;
    *out_size = total;
    return TDB_SUCCESS;
}

/**
 * rt_take_bytes
 * read one length-prefixed run out of a serialized block, bounds-checked against what is left, so a
 * block claiming more than it holds is refused rather than read past
 * @param p the read cursor, advanced past the length and the bytes
 * @param rem bytes left in the block, decremented by what this read
 * @param out_bytes receives the copied run, left NULL for a zero-length one
 * @param out_size receives the run length
 * @return TDB_SUCCESS, TDB_ERR_CORRUPTION, or TDB_ERR_MEMORY
 */
static int rt_take_bytes(const uint8_t **p, size_t *rem, uint8_t **out_bytes, size_t *out_size)
{
    if (*rem < sizeof(uint32_t)) return TDB_ERR_CORRUPTION;
    const uint32_t n = tdb_decode_be32(*p);
    *p += sizeof(uint32_t);
    *rem -= sizeof(uint32_t);

    if (*rem < n) return TDB_ERR_CORRUPTION;
    *out_size = n;
    *out_bytes = NULL;
    if (n == 0) return TDB_SUCCESS;

    *out_bytes = malloc(n);
    if (!*out_bytes) return TDB_ERR_MEMORY;
    memcpy(*out_bytes, *p, n);
    *p += n;
    *rem -= n;
    return TDB_SUCCESS;
}

/**
 * rt_read_fragment
 * read one fragment out of a serialized block straight into the next slot of the set
 *
 * the block already holds the fragmented form, so it is rebuilt as it is read rather than replayed
 * through the merge one sequence at a time -- replaying it refragments the whole set per sequence
 * and costs the square of the fragment count, which on a large block is seconds spent opening an
 * sstable. what the merge enforced as a side effect of rebuilding is checked here instead, so a
 * block not in that form is refused rather than quietly turned into a different set
 * @param p the read cursor, advanced past the fragment
 * @param rem bytes left in the block, decremented by what this read
 * @param set the set being filled, sized to the fragment count the block declared
 * @return TDB_SUCCESS, TDB_ERR_CORRUPTION, or TDB_ERR_MEMORY
 */
static int rt_read_fragment(const uint8_t **p, size_t *rem, range_tombstone_set_t *set)
{
    if (set->count >= set->capacity) return TDB_ERR_CORRUPTION;

    uint8_t *lo = NULL;
    uint8_t *hi = NULL;
    size_t lo_size = 0;
    size_t hi_size = 0;

    int rc = rt_take_bytes(p, rem, &lo, &lo_size);
    if (rc == TDB_SUCCESS) rc = rt_take_bytes(p, rem, &hi, &hi_size);
    if (rc == TDB_SUCCESS && *rem < sizeof(uint32_t)) rc = TDB_ERR_CORRUPTION;
    if (rc != TDB_SUCCESS)
    {
        free(lo);
        free(hi);
        return rc;
    }

    const uint32_t seq_count = tdb_decode_be32(*p);
    *p += sizeof(uint32_t);
    *rem -= sizeof(uint32_t);

    /* a fragment covered by nothing is not a fragment, and one claiming more sequences than the
     * block has room for is a length the bytes cannot support */
    if (seq_count == 0 || *rem / sizeof(uint64_t) < seq_count)
    {
        free(lo);
        free(hi);
        return TDB_ERR_CORRUPTION;
    }

    uint64_t *seqs = malloc(seq_count * sizeof(uint64_t));
    if (!seqs)
    {
        free(lo);
        free(hi);
        return TDB_ERR_MEMORY;
    }
    for (uint32_t s = 0; s < seq_count; s++)
    {
        seqs[s] = tdb_decode_be64(*p);
        *p += sizeof(uint64_t);
        *rem -= sizeof(uint64_t);
    }

    /* the append is what decides whether these fragments are a fragmentation at all. a block whose
     * bytes are well formed but whose contents are not one is corrupt rather than a bad argument */
    rc = range_tombstone_set_append_fragment(set, lo, lo_size, hi, hi_size, seqs, seq_count);
    if (rc == TDB_ERR_INVALID_ARGS) rc = TDB_ERR_CORRUPTION;

    free(seqs);
    free(lo);
    free(hi);
    return rc;
}

int range_tombstone_set_deserialize(const uint8_t *data, const size_t size,
                                    range_tombstone_set_t **out)
{
    if (!data || !out) return TDB_ERR_INVALID_ARGS;
    if (size < sizeof(uint8_t) + sizeof(uint32_t)) return TDB_ERR_CORRUPTION;

    const uint8_t *p = data;
    size_t rem = size;
    if (*p++ != RT_BLOCK_VERSION) return TDB_ERR_CORRUPTION;
    rem -= sizeof(uint8_t);

    const uint32_t count = tdb_decode_be32(p);
    p += sizeof(uint32_t);
    rem -= sizeof(uint32_t);

    /* the count is bounded by what the remaining bytes could hold, so a block naming a count it has
     * no room for is refused before any of it is allocated */
    if (rem / RT_BLOCK_MIN_FRAGMENT_BYTES < count) return TDB_ERR_CORRUPTION;

    range_tombstone_set_t *set = range_tombstone_set_new();
    if (!set) return TDB_ERR_MEMORY;

    /* sized once to the count the block declared, which the bound above has already weighed against
     * the bytes actually left */
    if (count > 0)
    {
        set->frags = calloc(count, sizeof(rt_fragment_t));
        if (!set->frags)
        {
            range_tombstone_set_free(set);
            return TDB_ERR_MEMORY;
        }
        set->capacity = count;
    }

    int rc = TDB_SUCCESS;
    for (uint32_t i = 0; i < count && rc == TDB_SUCCESS; i++) rc = rt_read_fragment(&p, &rem, set);

    if (rc != TDB_SUCCESS)
    {
        range_tombstone_set_free(set);
        return rc;
    }
    *out = set;
    return TDB_SUCCESS;
}

int range_tombstone_prefix_successor(const uint8_t *prefix, const size_t prefix_size,
                                     uint8_t **out_hi, size_t *out_hi_size)
{
    if (!out_hi || !out_hi_size) return TDB_ERR_INVALID_ARGS;
    if (prefix_size > 0 && !prefix) return TDB_ERR_INVALID_ARGS;

    size_t n = prefix_size;
    while (n > 0 && prefix[n - 1] == RT_KEY_BYTE_MAX) n--;

    /* a prefix that is nothing but 0xff bytes, the empty prefix included, has every key at or above
     * it under the order, so the interval it opens has no upper bound to name */
    if (n == 0)
    {
        *out_hi = NULL;
        *out_hi_size = RT_UNBOUNDED_ABOVE;
        return TDB_SUCCESS;
    }

    uint8_t *hi = malloc(n);
    if (!hi) return TDB_ERR_MEMORY;
    memcpy(hi, prefix, n);
    hi[n - 1]++;

    *out_hi = hi;
    *out_hi_size = n;
    return TDB_SUCCESS;
}
