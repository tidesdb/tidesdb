/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "range_filter/range_filter_dtrie.h"

#include <string.h>

#include "base/errors.h" /* TDB_SUCCESS and the TDB_ERR_* result codes */

/* bits read or compared at a time */
#define RF_DT_WINDOW 64

/* a trie of n keys has n leaves and n - 1 branches */
#define RF_DT_MAX_NODES (2 * RANGE_FILTER_DTRIE_MAX_KEYS)

/* the format bit's values, naming how path lengths are written */
#define RF_DT_FORMAT_UNARY 0
#define RF_DT_FORMAT_GAMMA 1

/* the position of a word's lowest bit counted from its top, turning a count of leading zeros into
 * the index of the highest set bit */
#define RF_DT_TOP_BIT 63

/* the most leading zeros an elias-gamma length may have, past any path a trie can hold */
#define RF_DT_GAMMA_MAX_ZEROS 32

/**
 * rf_dt_node_t
 * one node of a trie being built, in preorder
 * @param key the first key under the node, whose bits give the path
 * @param off where the node starts in the tails, past the bit that chose it
 * @param path the length of the shared path below a branch
 * @param leaf 1 for a leaf, 0 for a branch
 */
typedef struct
{
    size_t key;
    size_t off;
    size_t path;
    int leaf;
} rf_dt_node_t;

/**
 * rf_dt_span_t
 * keys first through last, sharing every bit before off, waiting to become a node
 * @param first the first key
 * @param last the last key
 * @param off where they start to be told apart
 */
typedef struct
{
    size_t first;
    size_t last;
    size_t off;
} rf_dt_span_t;

/**
 * rf_dt_state_t
 * where a walk of the trie stands against each endpoint
 * @param off how many bits of the tail the path so far knows
 * @param lo the path against the low endpoint's tail as far as it goes, -1 below, 0 equal, 1 above
 * @param hi the same against the high endpoint's tail
 */
typedef struct
{
    size_t off;
    int lo;
    int hi;
} rf_dt_state_t;

/* the first position at or after from where a and b differ once padded with zeros, or SIZE_MAX
 * when they never do */
static size_t rf_dt_padded_diff(const range_filter_bits_t *a, const range_filter_bits_t *b,
                                size_t from)
{
    const size_t end = a->nbits > b->nbits ? a->nbits : b->nbits;
    for (size_t at = from; at < end; at += RF_DT_WINDOW)
    {
        const uint64_t x =
            range_filter_bits_get(a, at, RF_DT_WINDOW) ^ range_filter_bits_get(b, at, RF_DT_WINDOW);
        if (x != 0) return at + (size_t)TDB_CLZ64(x);
    }
    return SIZE_MAX;
}

/* the bits elias-gamma takes for a path of length p, written as p + 1 so that 0 has a code */
static size_t rf_dt_gamma_bits(size_t p)
{
    const unsigned zeros = (unsigned)(RF_DT_TOP_BIT - TDB_CLZ64((uint64_t)p + 1));
    return 2 * (size_t)zeros + 1;
}

/* lay the group's trie out in preorder, returning the node count, or 0 when two tails are equal
 * once padded */
static size_t rf_dt_shape(const range_filter_bits_t *keys, size_t n, size_t tail_off,
                          rf_dt_node_t *nodes)
{
    rf_dt_span_t stack[RANGE_FILTER_DTRIE_MAX_KEYS];
    size_t sp = 0, count = 0;
    stack[sp++] = (rf_dt_span_t){0, n - 1, tail_off};
    while (sp > 0 && count < RF_DT_MAX_NODES)
    {
        const rf_dt_span_t s = stack[--sp];
        if (s.first == s.last)
        {
            nodes[count++] = (rf_dt_node_t){s.first, s.off, 0, 1};
            continue;
        }
        /* the keys are in order, so what the first and last share every key between shares */
        const size_t d = rf_dt_padded_diff(&keys[s.first], &keys[s.last], s.off);
        if (d == SIZE_MAX) return 0;
        size_t split = s.first + 1;
        while (split < s.last && range_filter_bits_get(&keys[split], d, 1) == 0) split++;
        nodes[count++] = (rf_dt_node_t){s.first, s.off, d - s.off, 0};
        /* the right child waits under the left, so preorder visits the left first */
        stack[sp++] = (rf_dt_span_t){split, s.last, d + 1};
        stack[sp++] = (rf_dt_span_t){s.first, split - 1, d + 1};
    }
    return count;
}

/* append n copies of bit, a field at a time */
static int rf_dt_append_run(range_filter_bits_t *out, int bit, size_t n)
{
    while (n > 0)
    {
        const unsigned take = n < RF_DT_WINDOW ? (unsigned)n : RF_DT_WINDOW;
        if (range_filter_bits_append(out, bit ? ~UINT64_C(0) : 0, take) != 0) return -1;
        n -= take;
    }
    return 0;
}

/* append a path length in the chosen format */
static int rf_dt_append_length(range_filter_bits_t *out, int format, size_t p)
{
    if (format == RF_DT_FORMAT_UNARY)
        return rf_dt_append_run(out, 1, p) == 0 && range_filter_bits_append(out, 0, 1) == 0 ? 0
                                                                                            : -1;
    const uint64_t v = (uint64_t)p + 1;
    const unsigned zeros = (unsigned)(RF_DT_TOP_BIT - TDB_CLZ64(v));
    if (range_filter_bits_append(out, 0, zeros) != 0) return -1;
    return range_filter_bits_append(out, v, zeros + 1);
}

/* append the nodes, the trailing strings and the zero fill */
static int rf_dt_emit(const range_filter_bits_t *keys, const rf_dt_node_t *nodes, size_t count,
                      int format, size_t trail, size_t fill, range_filter_bits_t *out)
{
    if (range_filter_bits_append(out, (uint64_t)format, 1) != 0) return -1;
    for (size_t i = 0; i < count; i++)
    {
        const rf_dt_node_t *nd = &nodes[i];
        if (nd->leaf)
        {
            if (range_filter_bits_append(out, 1, 1) != 0) return -1;
            continue;
        }
        if (range_filter_bits_append(out, 0, 1) != 0 ||
            rf_dt_append_length(out, format, nd->path) != 0 ||
            range_filter_bits_append_range(out, &keys[nd->key], nd->off, nd->path) != 0)
            return -1;
    }
    /* leaves fall in preorder in key order, so the trailing strings follow the keys */
    for (size_t i = 0; i < count; i++)
        if (nodes[i].leaf &&
            range_filter_bits_append_range(out, &keys[nodes[i].key], nodes[i].off, trail) != 0)
            return -1;
    return rf_dt_append_run(out, 0, fill);
}

int range_filter_dtrie_encode(const range_filter_bits_t *keys, size_t n, size_t tail_off,
                              size_t budget_bits, range_filter_bits_t *out, int *fitted)
{
    if (fitted) *fitted = 0;
    if (!keys || !out || !fitted || n < 2 || n > RANGE_FILTER_DTRIE_MAX_KEYS)
        return TDB_ERR_INVALID_ARGS;
    rf_dt_node_t nodes[RF_DT_MAX_NODES];
    const size_t count = rf_dt_shape(keys, n, tail_off, nodes);
    if (count == 0) return TDB_SUCCESS;

    /* the format bit, a bit per node, every path, and each format's lengths */
    size_t base = 1 + count, unary = 0, gamma = 0;
    for (size_t i = 0; i < count; i++)
    {
        if (nodes[i].leaf) continue;
        base += nodes[i].path;
        unary += nodes[i].path + 1;
        gamma += rf_dt_gamma_bits(nodes[i].path);
    }
    const int format = gamma < unary ? RF_DT_FORMAT_GAMMA : RF_DT_FORMAT_UNARY;
    const size_t trie_bits = base + (format == RF_DT_FORMAT_GAMMA ? gamma : unary);
    if (trie_bits > budget_bits) return TDB_SUCCESS;
    const size_t trail = (budget_bits - trie_bits) / n;
    const size_t fill = budget_bits - trie_bits - trail * n;

    const size_t start = out->nbits;
    if (rf_dt_emit(keys, nodes, count, format, trail, fill, out) != 0)
    {
        range_filter_bits_truncate(out, start);
        return TDB_ERR_MEMORY;
    }
    *fitted = 1;
    return TDB_SUCCESS;
}

/* read a path length at *pos in the given format, never reaching limit */
static int rf_dt_read_length(const range_filter_bits_t *src, int format, size_t *pos, size_t limit,
                             size_t *p)
{
    size_t at = *pos, len = 0;
    if (format == RF_DT_FORMAT_UNARY)
    {
        while (at < limit && range_filter_bits_get(src, at, 1) == 1)
        {
            len++;
            at++;
        }
        if (at >= limit) return TDB_ERR_CORRUPTION;
        *pos = at + 1;
        *p = len;
        return TDB_SUCCESS;
    }
    unsigned zeros = 0;
    while (at < limit && zeros <= RF_DT_GAMMA_MAX_ZEROS && range_filter_bits_get(src, at, 1) == 0)
    {
        zeros++;
        at++;
    }
    if (zeros > RF_DT_GAMMA_MAX_ZEROS || at + zeros + 1 > limit) return TDB_ERR_CORRUPTION;
    const uint64_t v = range_filter_bits_get(src, at, zeros + 1);
    *pos = at + zeros + 1;
    *p = (size_t)(v - 1);
    return TDB_SUCCESS;
}

int range_filter_dtrie_parse(const range_filter_bits_t *src, size_t at, size_t limit,
                             range_filter_dtrie_t *out)
{
    if (!src || !out || at >= limit) return TDB_ERR_CORRUPTION;
    memset(out, 0, sizeof(*out));
    size_t pos = at;
    const int format = (int)range_filter_bits_get(src, pos++, 1);
    size_t open = 1, leaves = 0, branches = 0;
    while (open > 0)
    {
        if (pos >= limit) return TDB_ERR_CORRUPTION;
        if (range_filter_bits_get(src, pos++, 1) == 1)
        {
            /* a lone leaf would be a group of one, which never gets a trie */
            if (branches == 0) return TDB_ERR_CORRUPTION;
            leaves++;
            open--;
            continue;
        }
        size_t p = 0;
        if (branches + 1 >= RANGE_FILTER_DTRIE_MAX_KEYS ||
            rf_dt_read_length(src, format, &pos, limit, &p) != TDB_SUCCESS || p > limit - pos)
            return TDB_ERR_CORRUPTION;
        pos += p;
        branches++;
        open++;
    }
    out->at = at;
    out->keys = leaves;
    out->trie_bits = pos - at;
    return TDB_SUCCESS;
}

int range_filter_dtrie_set_budget(range_filter_dtrie_t *t, size_t budget_bits)
{
    if (!t || t->keys == 0 || t->trie_bits > budget_bits) return TDB_ERR_CORRUPTION;
    t->trail = (budget_bits - t->trie_bits) / t->keys;
    return TDB_SUCCESS;
}

/* carry a comparison over n bits of value, standing for tail bits off onward, against an
 * endpoint's tail. a comparison already decided stays decided */
static int rf_dt_cmp_value(int rel, const range_filter_dtrie_probe_t *pr, size_t off,
                           uint64_t value, unsigned n)
{
    if (rel != 0 || !pr->key || n == 0) return rel;
    const uint64_t theirs = range_filter_bits_get(pr->key, pr->tail_off + off, n);
    if (value == theirs) return 0;
    return value < theirs ? -1 : 1;
}

/* carry a comparison over n bits of src starting at from */
static int rf_dt_cmp_src(int rel, const range_filter_dtrie_probe_t *pr, size_t off,
                         const range_filter_bits_t *src, size_t from, size_t n)
{
    for (size_t done = 0; done < n && rel == 0 && pr->key; done += RF_DT_WINDOW)
    {
        const unsigned take = n - done < RF_DT_WINDOW ? (unsigned)(n - done) : RF_DT_WINDOW;
        rel = rf_dt_cmp_value(rel, pr, off + done, range_filter_bits_get(src, from + done, take),
                              take);
    }
    return rel;
}

/* move a state across n bits of path read from src */
static void rf_dt_step_src(rf_dt_state_t *s, const range_filter_dtrie_probe_t *lo,
                           const range_filter_dtrie_probe_t *hi, const range_filter_bits_t *src,
                           size_t from, size_t n)
{
    s->lo = rf_dt_cmp_src(s->lo, lo, s->off, src, from, n);
    s->hi = rf_dt_cmp_src(s->hi, hi, s->off, src, from, n);
    s->off += n;
}

/* move a state across the one bit that chose a child */
static void rf_dt_step_bit(rf_dt_state_t *s, const range_filter_dtrie_probe_t *lo,
                           const range_filter_dtrie_probe_t *hi, uint64_t bit)
{
    s->lo = rf_dt_cmp_value(s->lo, lo, s->off, bit, 1);
    s->hi = rf_dt_cmp_value(s->hi, hi, s->off, bit, 1);
    s->off += 1;
}

int range_filter_dtrie_may_contain(const range_filter_bits_t *src, const range_filter_dtrie_t *t,
                                   const range_filter_dtrie_probe_t *lo,
                                   const range_filter_dtrie_probe_t *hi)
{
    if (!src || !t || !lo || !hi || t->keys == 0) return 1;
    const size_t limit = t->at + t->trie_bits;
    const size_t trail_at = limit;
    const int format = (int)range_filter_bits_get(src, t->at, 1);
    size_t pos = t->at + 1, leaf = 0, sp = 0;
    rf_dt_state_t stack[RANGE_FILTER_DTRIE_MAX_KEYS];
    /* a side not tested holds for every key, as if the key sat above lo or below hi */
    rf_dt_state_t cur = {0, lo->key ? 0 : 1, hi->key ? 0 : -1};
    for (size_t node = 0; node < RF_DT_MAX_NODES && pos < limit; node++)
    {
        if (range_filter_bits_get(src, pos++, 1) == 1)
        {
            rf_dt_state_t end = cur;
            rf_dt_step_src(&end, lo, hi, src, trail_at + leaf * t->trail, t->trail);
            /* the key's tail is known this far, and cut there it lies in the range */
            if (end.lo >= 0 && end.hi <= 0) return 1;
            leaf++;
            if (sp == 0) return 0;
            cur = stack[--sp];
            continue;
        }
        size_t p = 0;
        if (rf_dt_read_length(src, format, &pos, limit, &p) != TDB_SUCCESS || p > limit - pos ||
            sp >= RANGE_FILTER_DTRIE_MAX_KEYS)
            return 1;
        rf_dt_step_src(&cur, lo, hi, src, pos, p);
        pos += p;
        rf_dt_state_t right = cur;
        rf_dt_step_bit(&right, lo, hi, 1);
        stack[sp++] = right;
        rf_dt_step_bit(&cur, lo, hi, 0);
    }
    return 1;
}
