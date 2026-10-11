/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "range_filter/range_filter_codec.h"

#include <stdlib.h>
#include <string.h>

#include "base/encoding/serialization.h" /* encode_varint, decode_varint */
#include "base/errors.h"                 /* TDB_SUCCESS and the TDB_ERR_* result codes */

/* every byte value a tree codes */
#define RF_SYMBOLS 256

/* the most a context's weights may total. every byte weighs at least one and the observed counts
 * share what is left, so a tree is bounded however skewed its bytes were */
#define RF_WEIGHT_BUDGET (UINT32_C(1) << 20)

/* the doubled-unit interval the bisection halves, wide enough to hold twice the weight budget so a
 * byte's midpoint is always a whole number */
#define RF_INTERVAL (UINT32_C(1) << RANGE_FILTER_CODEC_MAX_CODE_BITS)

/* a context must have been seen this many times to earn its own tree; fewer and its counts say too
 * little to beat the lower order it would otherwise fall back to */
#define RF_MIN_CONTEXT_COUNT 32

/* the order-2 counts are kept in an open-addressed table of this many slots, a transient of the
 * build. once it is half full, combinations not yet in it are no longer counted and their bytes
 * code at weight one, which costs compression and never order */
#define RF_ORDER2_SLOTS (UINT32_C(1) << 18)

/* the most entries the table takes, half its slots, so empty slots stay common enough that a probe
 * for a combination it does not hold ends quickly */
#define RF_ORDER2_MAX_USED (RF_ORDER2_SLOTS / 2)

/* the most slots one probe looks at. at half load a probe almost never runs this far, and the bound
 * is what keeps counting linear in the keys however the table fills -- without it, a full table
 * made every unseen combination walk all of it */
#define RF_ORDER2_MAX_PROBE 64

/* how far above what noise alone gives a context's statistic must be for it to earn a tree. a
 * context over random bytes sits near the noise level, and twice it is far out in that tail */
#define RF_CHI2_NOISE_FACTOR 2.0

/* a context identifier for the pair of bytes before a byte, the earlier one high */
#define RF_PAIR(a, b) ((uint32_t)(((uint32_t)(a) << 8) | (uint32_t)(b)))

/* how many distinct byte pairs an order-2 context can be */
#define RF_PAIRS (RF_SYMBOLS * RF_SYMBOLS)

/* the serialized model's version, moved only when this layout changes */
#define RF_CODEC_FORMAT_VERSION 10

/* the longest a varint this format writes can be */
#define RF_VARINT_MAX 10

/* a table slot that has never held a pair */
#define RF_SLOT_EMPTY 0

struct range_filter_codec_counts
{
    uint32_t order0[RF_SYMBOLS];
    uint32_t *order1;   /* RF_PAIRS counts, the preceding byte major */
    uint32_t *o2_keys;  /* the pair and the byte packed, plus one so zero marks an empty slot */
    uint32_t *o2_count; /* the count for the key in the same slot */
    uint32_t o2_used;
};

/* the bits an encoder gathers before handing them to the string, one word */
#define RF_ACC_BITS 64

/* a code table entry holds the code in its low bits and the code's length above them */
#define RF_ENTRY_LEN_SHIFT 24
#define RF_ENTRY_CODE_MASK ((UINT32_C(1) << RF_ENTRY_LEN_SHIFT) - 1)

/**
 * rf_tree_t
 * one context's code table, all a model needs once its trees are derived
 * @param entry each byte's code, right-aligned, with its length in bits above RF_ENTRY_LEN_SHIFT
 * @param order the context's order, 0, 1 or 2
 * @param id the context, a byte for order 1 or a pair for order 2, 0 for order 0
 */
typedef struct
{
    uint32_t entry[RF_SYMBOLS];
    uint8_t order;
    uint16_t id;
} rf_tree_t;

/**
 * rf_weights_t
 * the weights one context's tree is derived from, kept only while the model may be serialized
 * @param n_obs how many bytes weigh more than one
 * @param obs_sym those bytes, ascending
 * @param obs_extra what each weighs beyond one
 */
typedef struct
{
    uint16_t n_obs;
    uint8_t obs_sym[RF_SYMBOLS];
    uint32_t obs_extra[RF_SYMBOLS];
} rf_weights_t;

struct range_filter_codec
{
    int max_order;
    rf_tree_t order0;
    int16_t order1_tree[RF_SYMBOLS]; /* the tree for each preceding byte, or -1 for none */
    rf_tree_t *trees;                /* order 1 by id, then order 2 by id */
    int n_trees;
    int first_order2; /* index of the first order-2 tree in trees */
    /* the order-2 trees' pairs in the same order, apart from the trees so the search for a pair,
     * made for every byte, runs through a small array rather than one tree's lines per step */
    uint16_t *pair_ids;
    /* the order-0 weights then each tree's, or NULL once a loaded model has derived its trees and
     * has no further use for them */
    rf_weights_t *weights;
    /* a model built here encodes a whole table, so it also indexes every pair directly, one entry
     * past its tree or 0 for none, which spares each byte a search. a loaded model encodes two keys
     * a query and keeps the search instead of the table */
    uint16_t *pair_tree;
};

int range_filter_codec_counts_new(range_filter_codec_counts_t **out)
{
    if (!out) return TDB_ERR_INVALID_ARGS;
    *out = NULL;
    range_filter_codec_counts_t *c = calloc(1, sizeof(*c));
    if (!c) return TDB_ERR_MEMORY;
    c->order1 = calloc(RF_PAIRS, sizeof(*c->order1));
    c->o2_keys = calloc(RF_ORDER2_SLOTS, sizeof(*c->o2_keys));
    c->o2_count = calloc(RF_ORDER2_SLOTS, sizeof(*c->o2_count));
    if (!c->order1 || !c->o2_keys || !c->o2_count)
    {
        range_filter_codec_counts_free(c);
        return TDB_ERR_MEMORY;
    }
    *out = c;
    return TDB_SUCCESS;
}

void range_filter_codec_counts_free(range_filter_codec_counts_t *counts)
{
    if (!counts) return;
    free(counts->order1);
    free(counts->o2_keys);
    free(counts->o2_count);
    free(counts);
}

/* add one to the count for a byte after a pair, probing linearly from the pair's hash */
static void rf_counts_add_order2(range_filter_codec_counts_t *c, uint32_t pair, uint8_t sym)
{
    const uint32_t key = ((pair << 8) | sym) + 1;
    /* a multiplicative hash, so neighbouring pairs scatter across the table */
    uint32_t slot = (uint32_t)((key * UINT32_C(2654435761)) % RF_ORDER2_SLOTS);
    for (uint32_t probe = 0; probe < RF_ORDER2_MAX_PROBE; probe++)
    {
        if (c->o2_keys[slot] == key)
        {
            c->o2_count[slot]++;
            return;
        }
        if (c->o2_keys[slot] == RF_SLOT_EMPTY)
        {
            if (c->o2_used >= RF_ORDER2_MAX_USED) return;
            c->o2_keys[slot] = key;
            c->o2_count[slot] = 1;
            c->o2_used++;
            return;
        }
        slot = (slot + 1) % RF_ORDER2_SLOTS;
    }
}

void range_filter_codec_counts_add(range_filter_codec_counts_t *counts, const uint8_t *key,
                                   size_t key_size)
{
    if (!counts || !key) return;
    for (size_t i = 0; i < key_size; i++)
    {
        const uint8_t sym = key[i];
        counts->order0[sym]++;
        if (i >= 1) counts->order1[RF_PAIR(key[i - 1], sym)]++;
        if (i >= 2) rf_counts_add_order2(counts, RF_PAIR(key[i - 2], key[i - 1]), sym);
    }
}

/* the weight of every byte in a tree, one plus what it observed */
static void rf_tree_weights(const rf_weights_t *w, uint32_t *weight)
{
    for (int s = 0; s < RF_SYMBOLS; s++) weight[s] = 1;
    for (int i = 0; i < w->n_obs; i++) weight[w->obs_sym[i]] += w->obs_extra[i];
}

/* the first byte in [lo, hi) whose doubled midpoint reaches m, or hi if none does */
static int rf_first_reaching(const uint32_t *mid2, int lo, int hi, uint32_t m)
{
    while (lo < hi)
    {
        const int half = lo + (hi - lo) / 2;
        if (mid2[half] >= m)
            hi = half;
        else
            lo = half + 1;
    }
    return lo;
}

/**
 * rf_node_t
 * a subtree still to be coded, waiting on the traversal's stack
 * @param lo the first byte the subtree holds
 * @param hi one past the last byte it holds
 * @param a the low end of the interval its midpoints lie in
 * @param b the high end of that interval, exclusive
 * @param code the bits on the path from the root to it
 * @param len how many bits that path has
 */
typedef struct
{
    int lo, hi;
    uint32_t a, b;
    uint32_t code;
    int len;
} rf_node_t;

/* derive a tree's code for every byte by Mehlhorn's bisection, walking the tree once. at each node
 * the interval is halved and the bytes whose midpoints fall in the lower half go left with a 0. a
 * halving that leaves every remaining byte on one side writes no bit, so no code carries a branch
 * with nothing on its other side. the midpoints are distinct whole numbers inside an interval of
 * 2^21, so a path halves at most 21 times before a single byte is left -- which bounds both a
 * code's length and the stack, since every entry on it is the right branch of a node on the
 * current path */
static int rf_tree_derive(rf_tree_t *t, const rf_weights_t *w)
{
    uint32_t weight[RF_SYMBOLS];
    uint32_t mid2[RF_SYMBOLS];
    rf_tree_weights(w, weight);
    uint32_t before = 0;
    for (int s = 0; s < RF_SYMBOLS; s++)
    {
        /* twice the weight before the byte plus its own, the midpoint of its span in doubled
         * units, strictly increasing since every weight is at least one */
        mid2[s] = 2 * before + weight[s];
        before += weight[s];
    }
    if (before > RF_WEIGHT_BUDGET) return -1;

    rf_node_t stack[RANGE_FILTER_CODEC_MAX_CODE_BITS + 1];
    int depth = 0;
    rf_node_t n = {.lo = 0, .hi = RF_SYMBOLS, .a = 0, .b = RF_INTERVAL, .code = 0, .len = 0};
    int coded = 0;
    /* each pass either codes a byte or halves the current node's interval, and a node is halved at
     * most 21 times, so the passes are bounded by the bytes times that */
    for (int pass = 0; pass < RF_SYMBOLS * (RANGE_FILTER_CODEC_MAX_CODE_BITS + 2); pass++)
    {
        if (n.hi - n.lo == 1)
        {
            t->entry[n.lo] = n.code | ((uint32_t)n.len << RF_ENTRY_LEN_SHIFT);
            if (++coded == RF_SYMBOLS) return 0;
            if (depth == 0) return -1;
            n = stack[--depth];
            continue;
        }
        if (n.b - n.a <= 1 || n.len > RANGE_FILTER_CODEC_MAX_CODE_BITS) return -1;
        const uint32_t m = n.a + (n.b - n.a) / 2;
        const int split = rf_first_reaching(mid2, n.lo, n.hi, m);
        if (split == n.lo)
            n.a = m;
        else if (split == n.hi)
            n.b = m;
        else
        {
            if (depth >= RANGE_FILTER_CODEC_MAX_CODE_BITS + 1) return -1;
            stack[depth++] = (rf_node_t){.lo = split,
                                         .hi = n.hi,
                                         .a = m,
                                         .b = n.b,
                                         .code = (n.code << 1) | 1u,
                                         .len = n.len + 1};
            n.hi = split;
            n.b = m;
            n.code <<= 1;
            n.len++;
        }
    }
    return -1;
}

/* turn a context's byte counts into weights within the budget. each byte weighs one plus its share
 * of what is left of the budget, so the weights total at most the budget */
static void rf_tree_quantize(rf_weights_t *t, const uint32_t *count)
{
    uint64_t total = 0;
    for (int s = 0; s < RF_SYMBOLS; s++) total += count[s];
    t->n_obs = 0;
    if (total == 0) return;
    const uint64_t share = RF_WEIGHT_BUDGET - RF_SYMBOLS;
    for (int s = 0; s < RF_SYMBOLS; s++)
    {
        const uint32_t extra = (uint32_t)(((uint64_t)count[s] * share) / total);
        if (extra == 0) continue;
        t->obs_sym[t->n_obs] = (uint8_t)s;
        t->obs_extra[t->n_obs] = extra;
        t->n_obs++;
    }
}

/**
 * rf_candidate_t
 * a context that may earn its own tree, ranked by how far its bytes stray from those of the context
 * it would otherwise fall back to
 * @param gain the chi-square statistic of its bytes against that fallback, less what noise alone
 * gives, so it grows with the bits the context's own tree would save
 * @param order its order, 1 or 2
 * @param id the preceding byte or pair
 */
typedef struct
{
    double gain;
    uint8_t order;
    uint16_t id;
} rf_candidate_t;

/* the largest gain first, then lower order, then lower id, so the selection is deterministic */
static int rf_candidate_by_gain(const void *pa, const void *pb)
{
    const rf_candidate_t *a = pa, *b = pb;
    if (a->gain != b->gain) return a->gain > b->gain ? -1 : 1;
    if (a->order != b->order) return a->order < b->order ? -1 : 1;
    return a->id < b->id ? -1 : (a->id > b->id ? 1 : 0);
}

/* order 1 before order 2, each by id, which is the order lookups search and the format stores */
static int rf_candidate_by_id(const void *pa, const void *pb)
{
    const rf_candidate_t *a = pa, *b = pb;
    if (a->order != b->order) return a->order < b->order ? -1 : 1;
    return a->id < b->id ? -1 : (a->id > b->id ? 1 : 0);
}

/* keep a context seen often enough whose bytes stray from its fallback's by more than chance. a
 * context with nothing to learn, as every one is over random bytes, would cost a tree and a cache
 * line per byte coded and code no shorter. the statistic is the sum over its bytes of count squared
 * over expected, less the count, which needs only the bytes it saw */
static void rf_consider(rf_candidate_t *cand, int *n, uint8_t order, uint16_t id, double total,
                        double sum_sq_over_p)
{
    if (total < RF_MIN_CONTEXT_COUNT) return;
    const double chi2 = sum_sq_over_p / total - total;
    const double noise = (double)(RF_SYMBOLS - 1);
    if (chi2 <= RF_CHI2_NOISE_FACTOR * noise) return;
    cand[(*n)++] = (rf_candidate_t){.gain = chi2 - noise, .order = order, .id = id};
}

/* each byte's share of the order-0 counts, smoothed so no byte has a share of zero */
static void rf_order0_shares(const range_filter_codec_counts_t *c, double *p0)
{
    double n = RF_SYMBOLS;
    for (int s = 0; s < RF_SYMBOLS; s++) n += c->order0[s];
    for (int s = 0; s < RF_SYMBOLS; s++) p0[s] = (c->order0[s] + 1.0) / n;
}

/* the order-2 candidates, each measured against the order-1 context of its last byte */
static int rf_order2_candidates(const range_filter_codec_counts_t *c, const double *row_total,
                                rf_candidate_t *cand, int *n)
{
    double *sum = calloc(RF_PAIRS, sizeof(*sum));
    double *total = calloc(RF_PAIRS, sizeof(*total));
    if (!sum || !total)
    {
        free(sum);
        free(total);
        return TDB_ERR_MEMORY;
    }
    for (uint32_t i = 0; i < RF_ORDER2_SLOTS; i++)
    {
        if (c->o2_keys[i] == RF_SLOT_EMPTY) continue;
        const uint32_t key = c->o2_keys[i] - 1;
        const uint32_t pair = key >> 8, sym = key & 0xFF, last = pair & 0xFF;
        const double p = (c->order1[RF_PAIR(last, sym)] + 1.0) / (row_total[last] + RF_SYMBOLS);
        const double cnt = c->o2_count[i];
        sum[pair] += cnt * cnt / p;
        total[pair] += cnt;
    }
    for (uint32_t p = 0; p < RF_PAIRS; p++) rf_consider(cand, n, 2, (uint16_t)p, total[p], sum[p]);
    free(sum);
    free(total);
    return TDB_SUCCESS;
}

/* gather every context worth a tree, up to max_order */
static int rf_collect_candidates(const range_filter_codec_counts_t *c, int max_order,
                                 rf_candidate_t **out, int *n_out)
{
    rf_candidate_t *cand = malloc((RF_SYMBOLS + RF_PAIRS) * sizeof(*cand));
    if (!cand) return TDB_ERR_MEMORY;
    double p0[RF_SYMBOLS], row_total[RF_SYMBOLS];
    rf_order0_shares(c, p0);
    int n = 0;
    for (int b = 0; b < RF_SYMBOLS; b++)
    {
        double total = 0.0, sum = 0.0;
        for (int s = 0; s < RF_SYMBOLS; s++)
        {
            const double cnt = c->order1[RF_PAIR(b, s)];
            total += cnt;
            sum += cnt * cnt / p0[s];
        }
        row_total[b] = total;
        if (max_order >= 1) rf_consider(cand, &n, 1, (uint16_t)b, total, sum);
    }
    if (max_order >= 2 && rf_order2_candidates(c, row_total, cand, &n) != TDB_SUCCESS)
    {
        free(cand);
        return TDB_ERR_MEMORY;
    }
    *out = cand;
    *n_out = n;
    return TDB_SUCCESS;
}

/* fill the kept trees' byte counts from the counts, then quantize and derive each one */
static int rf_fill_trees(range_filter_codec_t *m, const range_filter_codec_counts_t *c)
{
    uint32_t(*count)[RF_SYMBOLS] = calloc((size_t)m->n_trees, sizeof(*count));
    int32_t *pair_tree = malloc(RF_PAIRS * sizeof(*pair_tree));
    if (!count || !pair_tree)
    {
        free(count);
        free(pair_tree);
        return TDB_ERR_MEMORY;
    }
    for (uint32_t p = 0; p < RF_PAIRS; p++) pair_tree[p] = -1;
    for (int i = 0; i < m->n_trees; i++)
    {
        const rf_tree_t *t = &m->trees[i];
        if (t->order == 1)
            for (int s = 0; s < RF_SYMBOLS; s++) count[i][s] = c->order1[RF_PAIR(t->id, s)];
        else
            pair_tree[t->id] = i;
    }
    for (uint32_t i = 0; i < RF_ORDER2_SLOTS; i++)
    {
        if (c->o2_keys[i] == RF_SLOT_EMPTY) continue;
        const uint32_t key = c->o2_keys[i] - 1;
        const int32_t at = pair_tree[key >> 8];
        if (at >= 0) count[at][key & 0xFF] += c->o2_count[i];
    }
    int rc = TDB_SUCCESS;
    for (int i = 0; i < m->n_trees && rc == TDB_SUCCESS; i++)
    {
        rf_tree_quantize(&m->weights[i + 1], count[i]);
        if (rf_tree_derive(&m->trees[i], &m->weights[i + 1]) != 0) rc = TDB_ERR_INVALID_ARGS;
    }
    free(count);
    free(pair_tree);
    return rc;
}

/* index the order-1 trees by preceding byte, find where the order-2 trees start, and list their
 * pairs for the search */
static int rf_index_trees(range_filter_codec_t *m)
{
    for (int b = 0; b < RF_SYMBOLS; b++) m->order1_tree[b] = -1;
    m->first_order2 = m->n_trees;
    m->max_order = 0;
    for (int i = 0; i < m->n_trees; i++)
    {
        const rf_tree_t *t = &m->trees[i];
        if (t->order == 1) m->order1_tree[t->id] = (int16_t)i;
        if (t->order == 2 && m->first_order2 == m->n_trees) m->first_order2 = i;
        if (t->order > m->max_order) m->max_order = t->order;
    }
    const int n2 = m->n_trees - m->first_order2;
    if (n2 == 0) return TDB_SUCCESS;
    m->pair_ids = malloc((size_t)n2 * sizeof(*m->pair_ids));
    if (!m->pair_ids) return TDB_ERR_MEMORY;
    for (int i = 0; i < n2; i++) m->pair_ids[i] = m->trees[m->first_order2 + i].id;
    return TDB_SUCCESS;
}

int range_filter_codec_build(const range_filter_codec_counts_t *counts, int max_order,
                             int max_contexts, range_filter_codec_t **out)
{
    if (!out) return TDB_ERR_INVALID_ARGS;
    *out = NULL;
    if (!counts || max_order < 0 || max_order > RANGE_FILTER_CODEC_MAX_ORDER || max_contexts < 0)
        return TDB_ERR_INVALID_ARGS;

    range_filter_codec_t *m = calloc(1, sizeof(*m));
    if (!m) return TDB_ERR_MEMORY;
    rf_candidate_t *cand = NULL;
    int n_cand = 0;
    int rc = rf_collect_candidates(counts, max_order, &cand, &n_cand);
    if (rc == TDB_SUCCESS)
    {
        qsort(cand, (size_t)n_cand, sizeof(*cand), rf_candidate_by_gain);
        if (n_cand > max_contexts) n_cand = max_contexts;
        qsort(cand, (size_t)n_cand, sizeof(*cand), rf_candidate_by_id);
        m->n_trees = n_cand;
        m->trees = n_cand > 0 ? calloc((size_t)n_cand, sizeof(*m->trees)) : NULL;
        m->weights = calloc((size_t)n_cand + 1, sizeof(*m->weights));
        if ((n_cand > 0 && !m->trees) || !m->weights) rc = TDB_ERR_MEMORY;
    }
    if (rc == TDB_SUCCESS)
    {
        rf_tree_quantize(&m->weights[0], counts->order0);
        if (rf_tree_derive(&m->order0, &m->weights[0]) != 0) rc = TDB_ERR_INVALID_ARGS;
        for (int i = 0; i < n_cand && rc == TDB_SUCCESS; i++)
        {
            m->trees[i].order = cand[i].order;
            m->trees[i].id = cand[i].id;
        }
        if (rc == TDB_SUCCESS) rc = rf_fill_trees(m, counts);
    }
    free(cand);
    if (rc != TDB_SUCCESS)
    {
        range_filter_codec_free(m);
        return rc;
    }
    rc = rf_index_trees(m);
    if (rc == TDB_SUCCESS && m->first_order2 < m->n_trees)
    {
        m->pair_tree = calloc(RF_PAIRS, sizeof(*m->pair_tree));
        if (!m->pair_tree) rc = TDB_ERR_MEMORY;
        for (int i = m->first_order2; i < m->n_trees && rc == TDB_SUCCESS; i++)
            m->pair_tree[m->trees[i].id] = (uint16_t)(i + 1);
    }
    if (rc != TDB_SUCCESS)
    {
        range_filter_codec_free(m);
        return rc;
    }
    *out = m;
    return TDB_SUCCESS;
}

/* the order-2 tree for a pair, found by binary search over the order-2 trees, or NULL */
static const rf_tree_t *rf_find_pair(const range_filter_codec_t *m, uint32_t pair)
{
    if (m->pair_tree) return m->pair_tree[pair] ? &m->trees[m->pair_tree[pair] - 1] : NULL;
    const int n2 = m->n_trees - m->first_order2;
    int lo = 0, hi = n2;
    while (lo < hi)
    {
        const int half = lo + (hi - lo) / 2;
        if (m->pair_ids[half] < pair)
            lo = half + 1;
        else
            hi = half;
    }
    return lo < n2 && m->pair_ids[lo] == pair ? &m->trees[m->first_order2 + lo] : NULL;
}

/* the tree that codes the byte at position i, falling back from order 2 to 1 to 0. the choice
 * depends only on the model and the bytes before i, which is what keeps two keys sharing a prefix
 * on the same tree at their first difference */
static const rf_tree_t *rf_tree_for(const range_filter_codec_t *m, const uint8_t *key, size_t i)
{
    if (i >= 2 && m->max_order >= 2)
    {
        const rf_tree_t *t = rf_find_pair(m, RF_PAIR(key[i - 2], key[i - 1]));
        if (t) return t;
    }
    if (i >= 1 && m->max_order >= 1 && m->order1_tree[key[i - 1]] >= 0)
        return &m->trees[m->order1_tree[key[i - 1]]];
    return &m->order0;
}

int range_filter_codec_encode(const range_filter_codec_t *codec, const uint8_t *key,
                              size_t key_size, range_filter_bits_t *out)
{
    if (!codec || !out || (!key && key_size > 0)) return TDB_ERR_INVALID_ARGS;
    /* codes gather in a word and the string takes a whole word at a time, since a code is a few
     * bits and appending each one alone made the append the cost of encoding */
    uint64_t acc = 0;
    unsigned held = 0;
    for (size_t i = 0; i < key_size; i++)
    {
        const rf_tree_t *t = rf_tree_for(codec, key, i);
        const uint32_t e = t->entry[key[i]];
        const unsigned len = e >> RF_ENTRY_LEN_SHIFT;
        const uint64_t code = e & RF_ENTRY_CODE_MASK;
        if (held + len < RF_ACC_BITS)
        {
            acc = (acc << len) | code;
            held += len;
            continue;
        }
        /* the word fills, so its last bits are the code's high ones and the rest start the next */
        const unsigned spill = held + len - RF_ACC_BITS;
        const unsigned room = len - spill;
        acc = room > 0 ? (acc << room) | (code >> spill) : acc;
        if (range_filter_bits_append(out, acc, RF_ACC_BITS) != 0) return TDB_ERR_MEMORY;
        acc = spill > 0 ? code & ((UINT64_C(1) << spill) - 1) : 0;
        held = spill;
    }
    if (held > 0 && range_filter_bits_append(out, acc, held) != 0) return TDB_ERR_MEMORY;
    return TDB_SUCCESS;
}

int range_filter_codec_order(const range_filter_codec_t *codec)
{
    return codec ? codec->max_order : 0;
}

int range_filter_codec_context_count(const range_filter_codec_t *codec)
{
    return codec ? codec->n_trees : 0;
}

size_t range_filter_codec_context_bytes(void)
{
    return sizeof(rf_tree_t);
}

size_t range_filter_codec_resident_bytes(const range_filter_codec_t *codec)
{
    if (!codec) return 0;
    size_t bytes = sizeof(*codec) + (size_t)codec->n_trees * sizeof(*codec->trees) +
                   (size_t)(codec->n_trees - codec->first_order2) * sizeof(*codec->pair_ids);
    if (codec->weights) bytes += ((size_t)codec->n_trees + 1) * sizeof(*codec->weights);
    if (codec->pair_tree) bytes += RF_PAIRS * sizeof(*codec->pair_tree);
    return bytes;
}

void range_filter_codec_free(range_filter_codec_t *codec)
{
    if (!codec) return;
    free(codec->trees);
    free(codec->weights);
    free(codec->pair_ids);
    free(codec->pair_tree);
    free(codec);
}

/* ===== serialization ===== */

/* the most bytes one tree's weights can take, a count and every byte with its weight */
#define RF_TREE_MAX_BYTES (RF_VARINT_MAX + RF_SYMBOLS * (1 + RF_VARINT_MAX))

/* a tree's header, its order and the byte or pair it follows, before its weights */
#define RF_TREE_HEAD_BYTES 3

/* write a tree's weights, the bytes that weigh more than one with what each weighs beyond it */
static size_t rf_put_weights(const rf_weights_t *t, uint8_t *p)
{
    size_t at = (size_t)encode_varint(p, t->n_obs);
    for (int i = 0; i < t->n_obs; i++)
    {
        p[at++] = t->obs_sym[i];
        at += (size_t)encode_varint(p + at, t->obs_extra[i]);
    }
    return at;
}

int range_filter_codec_serialize(const range_filter_codec_t *codec, uint8_t **out, size_t *out_size)
{
    if (!out || !out_size) return TDB_ERR_INVALID_ARGS;
    *out = NULL;
    *out_size = 0;
    /* a loaded model kept only its code tables, and codes cannot be turned back into weights */
    if (!codec || !codec->weights) return TDB_ERR_INVALID_ARGS;
    const size_t cap = 2 + RF_VARINT_MAX + RF_TREE_MAX_BYTES +
                       (size_t)codec->n_trees * (RF_TREE_HEAD_BYTES + RF_TREE_MAX_BYTES);
    uint8_t *buf = malloc(cap);
    if (!buf) return TDB_ERR_MEMORY;

    size_t at = 0;
    buf[at++] = RF_CODEC_FORMAT_VERSION;
    buf[at++] = (uint8_t)codec->max_order;
    at += (size_t)encode_varint(buf + at, (uint64_t)codec->n_trees);
    at += rf_put_weights(&codec->weights[0], buf + at);
    for (int i = 0; i < codec->n_trees; i++)
    {
        const rf_tree_t *t = &codec->trees[i];
        buf[at++] = t->order;
        buf[at++] = (uint8_t)(t->id >> 8);
        buf[at++] = (uint8_t)(t->id & 0xFF);
        at += rf_put_weights(&codec->weights[i + 1], buf + at);
    }
    *out = buf;
    *out_size = at;
    return TDB_SUCCESS;
}

/* read one varint within the bytes left, advancing past it */
static int rf_take_varint(const uint8_t **p, size_t *rem, uint64_t *value)
{
    const int max = *rem < RF_VARINT_MAX ? (int)*rem : RF_VARINT_MAX;
    const int used = decode_varint(*p, value, max);
    if (used <= 0) return -1;
    *p += used;
    *rem -= (size_t)used;
    return 0;
}

/* read a tree's weights, rejecting bytes out of order, a zero or oversized weight, or a total over
 * the budget, any of which would derive codes the writer never had */
static int rf_take_weights(const uint8_t **p, size_t *rem, rf_weights_t *t)
{
    uint64_t n = 0;
    if (rf_take_varint(p, rem, &n) != 0 || n > RF_SYMBOLS) return -1;
    uint64_t total = RF_SYMBOLS;
    int prev = -1;
    t->n_obs = (uint16_t)n;
    for (uint64_t i = 0; i < n; i++)
    {
        if (*rem < 1) return -1;
        const int sym = **p;
        (*p)++;
        (*rem)--;
        uint64_t extra = 0;
        if (sym <= prev || rf_take_varint(p, rem, &extra) != 0 || extra == 0) return -1;
        total += extra;
        if (total > RF_WEIGHT_BUDGET) return -1;
        t->obs_sym[i] = (uint8_t)sym;
        t->obs_extra[i] = (uint32_t)extra;
        prev = sym;
    }
    return 0;
}

/* read the trees after the order-0 one, each after the one before it in the order lookups need */
static int rf_take_trees(const uint8_t **p, size_t *rem, range_filter_codec_t *m, int max_order)
{
    int prev_order = 1, prev_id = -1;
    for (int i = 0; i < m->n_trees; i++)
    {
        if (*rem < RF_TREE_HEAD_BYTES) return -1;
        rf_tree_t *t = &m->trees[i];
        const int order = (*p)[0];
        const int id = ((*p)[1] << 8) | (*p)[2];
        *p += RF_TREE_HEAD_BYTES;
        *rem -= RF_TREE_HEAD_BYTES;
        if (order < 1 || order > max_order || order < prev_order) return -1;
        if (order == prev_order && id <= prev_id) return -1;
        if (order == 1 && id >= RF_SYMBOLS) return -1;
        t->order = (uint8_t)order;
        t->id = (uint16_t)id;
        if (rf_take_weights(p, rem, &m->weights[i + 1]) != 0) return -1;
        prev_id = id;
        prev_order = order;
    }
    return 0;
}

int range_filter_codec_deserialize(const uint8_t *data, size_t size, range_filter_codec_t **out)
{
    if (!out) return TDB_ERR_INVALID_ARGS;
    *out = NULL;
    if (!data || size < 2) return TDB_ERR_INVALID_ARGS;
    if (data[0] != RF_CODEC_FORMAT_VERSION || data[1] > RANGE_FILTER_CODEC_MAX_ORDER)
        return TDB_ERR_CORRUPTION;
    const int max_order = data[1];
    const uint8_t *p = data + 2;
    size_t rem = size - 2;

    range_filter_codec_t *m = calloc(1, sizeof(*m));
    if (!m) return TDB_ERR_MEMORY;
    uint64_t n_trees = 0;
    int rc = TDB_SUCCESS;
    /* every tree takes its header and a weight count, so a count the bytes left cannot hold is
     * refused before anything is sized by it */
    if (rf_take_varint(&p, &rem, &n_trees) != 0 || n_trees > (uint64_t)(RF_SYMBOLS + RF_PAIRS) ||
        n_trees > rem / (RF_TREE_HEAD_BYTES + 1))
        rc = TDB_ERR_CORRUPTION;
    if (rc == TDB_SUCCESS)
    {
        m->n_trees = (int)n_trees;
        m->trees = n_trees > 0 ? calloc((size_t)n_trees, sizeof(*m->trees)) : NULL;
        m->weights = calloc((size_t)n_trees + 1, sizeof(*m->weights));
        if ((n_trees > 0 && !m->trees) || !m->weights) rc = TDB_ERR_MEMORY;
    }
    if (rc == TDB_SUCCESS && rf_take_weights(&p, &rem, &m->weights[0]) != 0)
        rc = TDB_ERR_CORRUPTION;
    if (rc == TDB_SUCCESS && rf_take_trees(&p, &rem, m, max_order) != 0) rc = TDB_ERR_CORRUPTION;
    if (rc == TDB_SUCCESS && rem != 0) rc = TDB_ERR_CORRUPTION;
    /* the trees are derived only once every byte of the model has checked out, so damaged input is
     * refused at the cost of reading it and never at the cost of deriving from it */
    if (rc == TDB_SUCCESS && rf_tree_derive(&m->order0, &m->weights[0]) != 0)
        rc = TDB_ERR_CORRUPTION;
    for (int i = 0; i < m->n_trees && rc == TDB_SUCCESS; i++)
        if (rf_tree_derive(&m->trees[i], &m->weights[i + 1]) != 0) rc = TDB_ERR_CORRUPTION;
    if (rc != TDB_SUCCESS)
    {
        range_filter_codec_free(m);
        return rc;
    }
    /* the writer records the deepest order its trees hold, so any other value is not its model */
    rc = rf_index_trees(m);
    if (rc == TDB_SUCCESS && m->max_order != max_order) rc = TDB_ERR_CORRUPTION;
    if (rc != TDB_SUCCESS)
    {
        range_filter_codec_free(m);
        return rc;
    }
    /* a loaded model only encodes, so its weights go once the trees are derived from them */
    free(m->weights);
    m->weights = NULL;
    *out = m;
    return TDB_SUCCESS;
}
