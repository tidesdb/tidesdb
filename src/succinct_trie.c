/*
 *
 * Copyright (C) TidesDB
 *
 * Original Author: Alex Gaetano Padula
 *
 * Licensed under the Mozilla Public License, v. 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.mozilla.org/en-US/MPL/2.0/
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "succinct_trie.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "block_manager.h"
#include "compat.h"

#define BIT_SET(bm, i) ((bm)[(i) >> 3] |= (1u << ((i)&7)))
#define BIT_GET(bm, i) (((bm)[(i) >> 3] >> ((i)&7)) & 1u)

/* cross-platform popcount */
#if defined(__GNUC__) || defined(__clang__)
#define POPCOUNT64(x) __builtin_popcountll(x)
#define POPCOUNT32(x) __builtin_popcount(x)
#elif defined(_MSC_VER)
#include <intrin.h>
#if defined(_M_X64) || defined(_M_AMD64)
#define POPCOUNT64(x) __popcnt64(x)
#else
/* x86 doesn't have __popcnt64, use two __popcnt calls */
#define POPCOUNT64(x) (__popcnt((uint32_t)(x)) + __popcnt((uint32_t)((x) >> 32)))
#endif
#define POPCOUNT32(x) __popcnt(x)
#else
/* fallback popcount */
/*
 * popcount64_fallback
 * @param x the 64-bit integer to count 1s in
 */
static inline int popcount64_fallback(uint64_t x)
{
    x = x - ((x >> 1) & 0x5555555555555555ULL);
    x = (x & 0x3333333333333333ULL) + ((x >> 2) & 0x3333333333333333ULL);
    x = (x + (x >> 4)) & 0x0F0F0F0F0F0F0F0FULL;
    return (int)((x * 0x0101010101010101ULL) >> 56);
}
#define POPCOUNT64(x) popcount64_fallback(x)
#define POPCOUNT32(x) popcount64_fallback(x)
#endif

/* built-in comparator functions */
int succinct_trie_comparator_memcmp(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                                    size_t key2_size, void *ctx)
{
    (void)ctx;

    size_t min_size = key1_size < key2_size ? key1_size : key2_size;
    int cmp = memcmp(key1, key2, min_size);
    if (cmp != 0) return cmp < 0 ? -1 : 1;

    return (key1_size < key2_size) ? -1 : (key1_size > key2_size) ? 1 : 0;
}

int succinct_trie_comparator_string(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                                    size_t key2_size, void *ctx)
{
    (void)ctx;

    size_t min_len = key1_size < key2_size ? key1_size : key2_size;
    int cmp = strncmp((const char *)key1, (const char *)key2, min_len);

    if (cmp != 0) return cmp < 0 ? -1 : 1;

    /* if prefixes are equal, compare lengths */
    return (key1_size < key2_size) ? -1 : (key1_size > key2_size) ? 1 : 0;
}

/*
 * compute_lcp
 * compute longest common prefix
 * @param k1 the first key
 * @param len1 the length of the first key
 * @param k2 the second key
 * @param len2 the length of the second key
 * @return the length of the longest common prefix
 */
static size_t compute_lcp(const uint8_t *k1, size_t len1, const uint8_t *k2, size_t len2)
{
    size_t min_len = len1 < len2 ? len1 : len2;
    size_t lcp = 0;
    while (lcp < min_len && k1[lcp] == k2[lcp]) lcp++;
    return lcp;
}

/*
 * rank1
 * count 1s up to position i (exclusive) - optimized with popcount
 * @param bm the bitvector
 * @param i the position
 * @return the number of 1s up to position i (exclusive)
 */
static uint32_t rank1(const uint8_t *bm, uint32_t i)
{
    if (i == 0) return 0;

    uint32_t cnt = 0;
    uint32_t full_bytes = i / 8;
    uint32_t remaining_bits = i % 8;

    /* process full 64-bit words */
    uint32_t full_words = full_bytes / 8;
    const uint64_t *words = (const uint64_t *)bm;
    for (uint32_t w = 0; w < full_words; w++)
    {
        cnt += POPCOUNT64(words[w]);
    }

    /* process remaining full bytes */
    uint32_t byte_offset = full_words * 8;
    for (uint32_t b = byte_offset; b < full_bytes; b++)
    {
        cnt += POPCOUNT32(bm[b]);
    }

    /* process remaining bits in last byte */
    if (remaining_bits > 0)
    {
        uint8_t mask = (1u << remaining_bits) - 1;
        cnt += POPCOUNT32(bm[full_bytes] & mask);
    }

    return cnt;
}

/*
 * select0
 * find position of k-th 0 (1-indexed) - optimized with word-level scanning
 * @param bm the bitvector
 * @param max_bits the maximum number of bits
 * @param k the k-th 0 to find
 * @return the position of the k-th 0
 */
static uint32_t select0(const uint8_t *bm, uint32_t max_bits, uint32_t k)
{
    if (k == 0) return max_bits;

    uint32_t cnt = 0;
    uint32_t max_bytes = (max_bits + 7) / 8;

    /* scan bytes */
    for (uint32_t byte_idx = 0; byte_idx < max_bytes; byte_idx++)
    {
        uint8_t byte_val = bm[byte_idx];
        uint32_t zeros_in_byte = 8 - POPCOUNT32(byte_val);

        /* check if k-th zero is in this byte */
        if (cnt + zeros_in_byte >= k)
        {
            /* scan bits in this byte */
            uint32_t bit_offset = byte_idx * 8;
            for (uint32_t bit = 0; bit < 8 && bit_offset + bit < max_bits; bit++)
            {
                if (!(byte_val & (1u << bit)))
                {
                    cnt++;
                    if (cnt == k) return bit_offset + bit;
                }
            }
        }
        else
        {
            cnt += zeros_in_byte;
        }
    }

    return max_bits;
}

/*
 * get_children_start
 * get children start position in LOUDS for a node
 * @param trie the trie
 * @param node the node
 * @return children start position
 */
static uint32_t get_children_start(const succinct_trie_t *trie, uint32_t node)
{
    uint32_t zero_pos = select0(trie->louds, trie->louds_bits, node);
    if (zero_pos >= trie->louds_bits - 1) return trie->louds_bits;
    return zero_pos + 1;
}

succinct_trie_builder_t *succinct_trie_builder_new(const char *temp_dir,
                                                   succinct_trie_comparator_fn comparator,
                                                   void *comparator_ctx)
{
    succinct_trie_builder_t *builder = calloc(1, sizeof(succinct_trie_builder_t));
    if (!builder) return NULL;

    /* use platform-appropriate temp directory if none provided */
    const char *dir = temp_dir;
    if (!dir)
    {
#ifdef _WIN32
        dir = getenv("TEMP");
        if (!dir) dir = getenv("TMP");
        if (!dir) dir = ".";
#else
        dir = "/tmp";
#endif
    }
    char path[512];
    /* use both PID and thread ID to make filenames unique per thread */
    unsigned long tid = TDB_THREAD_ID();
    snprintf(path, sizeof(path), "%s/trie_labels_%d_%lu", dir, TDB_GETPID(), tid);
    if (block_manager_open((block_manager_t **)&builder->labels_bm, path,
                           BLOCK_MANAGER_SYNC_NONE) != 0)
    {
        free(builder);
        return NULL;
    }

    snprintf(path, sizeof(path), "%s/trie_parents_%d_%lu", dir, TDB_GETPID(), tid);
    if (block_manager_open((block_manager_t **)&builder->parents_bm, path,
                           BLOCK_MANAGER_SYNC_NONE) != 0)
    {
        block_manager_close((block_manager_t *)builder->labels_bm);
        free(builder);
        return NULL;
    }

    snprintf(path, sizeof(path), "%s/trie_child_ids_%d_%lu", dir, TDB_GETPID(), tid);
    if (block_manager_open((block_manager_t **)&builder->child_ids_bm, path,
                           BLOCK_MANAGER_SYNC_NONE) != 0)
    {
        block_manager_close((block_manager_t *)builder->parents_bm);
        block_manager_close((block_manager_t *)builder->labels_bm);
        free(builder);
        return NULL;
    }

    snprintf(path, sizeof(path), "%s/trie_term_%d_%lu", dir, TDB_GETPID(), tid);
    if (block_manager_open((block_manager_t **)&builder->term_bm, path, BLOCK_MANAGER_SYNC_NONE) !=
        0)
    {
        block_manager_close((block_manager_t *)builder->child_ids_bm);
        block_manager_close((block_manager_t *)builder->parents_bm);
        block_manager_close((block_manager_t *)builder->labels_bm);
        free(builder);
        return NULL;
    }

    snprintf(path, sizeof(path), "%s/trie_vals_%d_%lu", dir, TDB_GETPID(), tid);
    if (block_manager_open((block_manager_t **)&builder->vals_bm, path, BLOCK_MANAGER_SYNC_NONE) !=
        0)
    {
        block_manager_close((block_manager_t *)builder->term_bm);
        block_manager_close((block_manager_t *)builder->child_ids_bm);
        block_manager_close((block_manager_t *)builder->parents_bm);
        block_manager_close((block_manager_t *)builder->labels_bm);
        free(builder);
        return NULL;
    }

    /* alloc prev_key buffer */
    builder->prev_key_capacity = 256;
    builder->prev_key = malloc(builder->prev_key_capacity);
    if (!builder->prev_key)
    {
        block_manager_close((block_manager_t *)builder->vals_bm);
        block_manager_close((block_manager_t *)builder->term_bm);
        block_manager_close((block_manager_t *)builder->child_ids_bm);
        block_manager_close((block_manager_t *)builder->parents_bm);
        block_manager_close((block_manager_t *)builder->labels_bm);
        free(builder);
        return NULL;
    }

    /* alloc path stack for tracking node IDs at each depth */
    builder->path_capacity = 256;
    builder->path_stack = malloc(builder->path_capacity * sizeof(uint32_t));
    if (!builder->path_stack)
    {
        free(builder->prev_key);
        block_manager_close((block_manager_t *)builder->vals_bm);
        block_manager_close((block_manager_t *)builder->term_bm);
        block_manager_close((block_manager_t *)builder->child_ids_bm);
        block_manager_close((block_manager_t *)builder->parents_bm);
        block_manager_close((block_manager_t *)builder->labels_bm);
        free(builder);
        return NULL;
    }
    builder->path_stack[0] = 1; /* root at depth 0 */

    builder->comparator = comparator ? comparator : succinct_trie_comparator_memcmp;
    builder->comparator_ctx = comparator_ctx;
    builder->next_node_id = 2; /* node 1 is root */
    builder->n_nodes = 1;      /* root exists */
    builder->n_edges = 0;
    builder->n_vals = 0;
    builder->prev_key_len = 0;

    /* write terminal bit for root (always non-terminal) */
    uint8_t root_term = 0;
    block_manager_block_t *block = block_manager_block_create(sizeof(uint8_t), &root_term);
    if (!block || block_manager_block_write((block_manager_t *)builder->term_bm, block) < 0)
    {
        if (block) block_manager_block_free(block);
        free(builder->prev_key);
        block_manager_close((block_manager_t *)builder->vals_bm);
        block_manager_close((block_manager_t *)builder->term_bm);
        block_manager_close((block_manager_t *)builder->parents_bm);
        block_manager_close((block_manager_t *)builder->labels_bm);
        free(builder);
        return NULL;
    }
    block_manager_block_free(block);

    return builder;
}

int succinct_trie_builder_add(succinct_trie_builder_t *builder, const uint8_t *key, size_t key_len,
                              int64_t value)
{
    if (!builder || !key)
    {
        return -1;
    }

    /* validate sorted order */
    if (builder->prev_key_len > 0)
    {
        int cmp = builder->comparator(builder->prev_key, builder->prev_key_len, key, key_len,
                                      builder->comparator_ctx);

        if (cmp >= 0)
        {
            return -1; /* keys must be in ascending order */
        }
    }

    /* compute LCP with previous key */
    size_t lcp = compute_lcp(builder->prev_key, builder->prev_key_len, key, key_len);

    /* create new nodes for the suffix after LCP */
    for (size_t i = lcp; i < key_len; i++)
    {
        /* resize path stack if needed */
        if (i >= builder->path_capacity)
        {
            size_t new_cap = builder->path_capacity * 2;
            uint32_t *new_stack = realloc(builder->path_stack, new_cap * sizeof(uint32_t));
            if (!new_stack) return -1;
            builder->path_stack = new_stack;
            builder->path_capacity = new_cap;
        }

        /* parent is the node at depth i (or root if i==0) */
        uint32_t parent_id = (i == 0) ? 1 : builder->path_stack[i - 1];
        uint32_t child_node_id = builder->next_node_id++;
        uint8_t label = key[i];
        uint8_t is_terminal = (i == key_len - 1) ? 1 : 0;

        /* store this node in path stack */
        builder->path_stack[i] = child_node_id;

        /* write label */
        block_manager_block_t *block = block_manager_block_create(sizeof(uint8_t), &label);
        if (!block) return -1;
        if (block_manager_block_write((block_manager_t *)builder->labels_bm, block) < 0)
        {
            block_manager_block_free(block);
            return -1;
        }
        block_manager_block_free(block);

        /* write parent ID (little-endian) */
        uint8_t parent_buf[4];
        encode_uint32_le_compat(parent_buf, parent_id);
        block = block_manager_block_create(sizeof(uint32_t), parent_buf);
        if (!block) return -1;
        if (block_manager_block_write((block_manager_t *)builder->parents_bm, block) < 0)
        {
            block_manager_block_free(block);
            return -1;
        }
        block_manager_block_free(block);

        /* write child node ID (little-endian) */
        uint8_t child_buf[4];
        encode_uint32_le_compat(child_buf, child_node_id);
        block = block_manager_block_create(sizeof(uint32_t), child_buf);
        if (!block) return -1;
        if (block_manager_block_write((block_manager_t *)builder->child_ids_bm, block) < 0)
        {
            block_manager_block_free(block);
            return -1;
        }
        block_manager_block_free(block);

        /* write terminal flag */
        block = block_manager_block_create(sizeof(uint8_t), &is_terminal);
        if (!block) return -1;
        if (block_manager_block_write((block_manager_t *)builder->term_bm, block) < 0)
        {
            block_manager_block_free(block);
            return -1;
        }
        block_manager_block_free(block);

        /* write value if terminal */
        if (is_terminal && value != -1)
        {
            /* write value (little-endian) */
            uint8_t val_buf[8];
            encode_uint64_le_compat(val_buf, (uint64_t)value);
            block = block_manager_block_create(sizeof(int64_t), val_buf);
            if (!block) return -1;
            if (block_manager_block_write((block_manager_t *)builder->vals_bm, block) < 0)
            {
                block_manager_block_free(block);
                return -1;
            }
            block_manager_block_free(block);
            builder->n_vals++;
        }

        builder->n_edges++;
        builder->n_nodes++;
    }

    /* save current key as prev_key */
    if (key_len > builder->prev_key_capacity)
    {
        size_t new_cap = key_len * 2;
        uint8_t *new_buf = realloc(builder->prev_key, new_cap);
        if (!new_buf) return -1;
        builder->prev_key = new_buf;
        builder->prev_key_capacity = new_cap;
    }
    memcpy(builder->prev_key, key, key_len);
    builder->prev_key_len = key_len;

    return 0;
}

succinct_trie_t *succinct_trie_builder_build(succinct_trie_builder_t *builder)
{
    if (!builder) return NULL;
    succinct_trie_t *trie = calloc(1, sizeof(succinct_trie_t));
    if (!trie)
    {
        succinct_trie_builder_free(builder);
        return NULL;
    }

    trie->n_nodes = builder->n_nodes;
    trie->n_edges = builder->n_edges;
    trie->n_vals = builder->n_vals;
    trie->comparator = builder->comparator;
    trie->comparator_ctx = builder->comparator_ctx;

    /* read labels, parent IDs, and child IDs from disk */
    uint8_t *labels = malloc(builder->n_edges);
    uint32_t *parents = malloc(builder->n_edges * sizeof(uint32_t));
    uint32_t *child_ids = malloc(builder->n_edges * sizeof(uint32_t));
    if (!labels || !parents || !child_ids)
    {
        free(labels);
        free(parents);
        free(child_ids);
        free(trie);
        succinct_trie_builder_free(builder);
        return NULL;
    }

    block_manager_cursor_t *cursor = NULL;

    /* read labels */
    if (block_manager_cursor_init(&cursor, (block_manager_t *)builder->labels_bm) == 0)
    {
        uint32_t idx = 0;
        while (block_manager_cursor_has_next(cursor) > 0 && idx < builder->n_edges)
        {
            block_manager_block_t *block = block_manager_cursor_read(cursor);
            if (block)
            {
                labels[idx++] = *(uint8_t *)block->data;
                block_manager_block_free(block);
            }
            block_manager_cursor_next(cursor);
        }
        block_manager_cursor_free(cursor);
    }

    /* read parent IDs */
    if (block_manager_cursor_init(&cursor, (block_manager_t *)builder->parents_bm) == 0)
    {
        uint32_t idx = 0;
        while (block_manager_cursor_has_next(cursor) > 0 && idx < builder->n_edges)
        {
            block_manager_block_t *block = block_manager_cursor_read(cursor);
            if (block)
            {
                parents[idx++] = decode_uint32_le_compat((uint8_t *)block->data);
                block_manager_block_free(block);
            }
            block_manager_cursor_next(cursor);
        }
        block_manager_cursor_free(cursor);
    }

    /* read child IDs */
    if (block_manager_cursor_init(&cursor, (block_manager_t *)builder->child_ids_bm) == 0)
    {
        uint32_t idx = 0;
        while (block_manager_cursor_has_next(cursor) > 0 && idx < builder->n_edges)
        {
            block_manager_block_t *block = block_manager_cursor_read(cursor);
            if (block)
            {
                child_ids[idx++] = decode_uint32_le_compat((uint8_t *)block->data);
                block_manager_block_free(block);
            }
            block_manager_cursor_next(cursor);
        }
        block_manager_cursor_free(cursor);
    }

    /* build adjacency list -- children[node_id] = list of (label, child_id) */
    typedef struct child_entry
    {
        uint8_t label;
        uint32_t child_id;
        struct child_entry *next;
    } child_entry_t;

    /* allocate children array large enough for all node IDs (0 to next_node_id-1) */
    child_entry_t **children = calloc(builder->next_node_id, sizeof(child_entry_t *));
    if (!children)
    {
        free(labels);
        free(parents);
        free(child_ids);
        free(trie);
        succinct_trie_builder_free(builder);
        return NULL;
    }

    /* build adjacency list from edges */
    for (uint32_t i = 0; i < builder->n_edges; i++)
    {
        uint32_t parent = parents[i];
        uint32_t child = child_ids[i];
        uint8_t label = labels[i];

        child_entry_t *entry = malloc(sizeof(child_entry_t));
        entry->label = label;
        entry->child_id = child;
        entry->next = children[parent];
        children[parent] = entry;
    }

    /* sort children by label for each node */

    for (uint32_t node = 0; node < builder->next_node_id; node++)
    {
        if (!children[node]) continue;

        /* count children */
        int count = 0;
        for (child_entry_t *c = children[node]; c; c = c->next) count++;

        if (count == 0) continue;
        if (count == 1) continue; /* already sorted */

        /* sort using array */
        child_entry_t **arr = malloc(count * sizeof(child_entry_t *));
        if (!arr) continue;

        int idx = 0;
        for (child_entry_t *c = children[node]; c; c = c->next) arr[idx++] = c;

        /* bubble sort by label */
        for (int i = 0; i < count - 1; i++)
            for (int j = 0; j < count - i - 1; j++)
                if (arr[j]->label > arr[j + 1]->label)
                {
                    child_entry_t *tmp = arr[j];
                    arr[j] = arr[j + 1];
                    arr[j + 1] = tmp;
                }

        /* rebuild linked list in sorted order */
        children[node] = arr[0];
        for (int i = 0; i < count - 1; i++) arr[i]->next = arr[i + 1];
        arr[count - 1]->next = NULL;

        free(arr);
    }

    /* build LOUDS bitvector via BFS */
    /* LOUDS super-root (10) + for each node (children 1s + terminating 0) */
    trie->louds_bits = 2 + builder->n_nodes + builder->n_edges;
    uint32_t louds_bytes = (trie->louds_bits + 7) / 8;
    trie->louds = calloc(louds_bytes, 1);
    trie->labels = malloc(builder->n_edges);
    trie->edge_child = malloc(builder->n_edges * sizeof(uint32_t));
    if (!trie->louds || !trie->labels || !trie->edge_child)
    {
        free(trie->edge_child);
        free(trie->louds);
        free(trie->labels);
        free(labels);
        free(parents);
        free(child_ids);
        for (uint32_t i = 0; i < builder->next_node_id; i++)
        {
            child_entry_t *c = children[i];
            while (c)
            {
                child_entry_t *next = c->next;
                free(c);
                c = next;
            }
        }
        free(children);
        free(trie);
        succinct_trie_builder_free(builder);
        return NULL;
    }

    /* BFS to build LOUDS */
    uint32_t *queue = malloc((builder->n_nodes + 1) * sizeof(uint32_t));
    uint32_t *node_id_to_louds = calloc(builder->next_node_id, sizeof(uint32_t));
    uint32_t head = 0, tail = 0;
    uint32_t louds_pos = 0;
    uint32_t label_idx = 0;
    uint32_t louds_node_num = 1; /* LOUDS node numbering starts at 1 for root */

    /* super-root */
    BIT_SET(trie->louds, louds_pos);
    louds_pos++;
    louds_pos++; /* 0 bit */

    /* strt BFS from root (node 1) */
    queue[tail++] = 1;
    node_id_to_louds[1] = louds_node_num++; /* root is LOUDS node 1 */

    while (head < tail)
    {
        uint32_t node = queue[head++];

        /* write 1-bits for each child, then 0 */
        for (child_entry_t *c = children[node]; c; c = c->next)
        {
            if (louds_pos >= trie->louds_bits || label_idx >= trie->n_edges) break;
            BIT_SET(trie->louds, louds_pos);
            louds_pos++;
            trie->labels[label_idx] = c->label;

            /* assign LOUDS node number to this child */
            if (node_id_to_louds[c->child_id] == 0)
            {
                node_id_to_louds[c->child_id] = louds_node_num++;
            }
            trie->edge_child[label_idx] =
                node_id_to_louds[c->child_id]; /* store LOUDS node number */

            label_idx++;
            queue[tail] = c->child_id;
            tail++;
        }
        if (louds_pos < trie->louds_bits) louds_pos++; /* 0 bit to close node */
    }

    free(queue);
    free(labels);
    free(parents);
    free(child_ids);
    for (uint32_t i = 0; i < builder->next_node_id; i++)
    {
        child_entry_t *c = children[i];
        while (c)
        {
            child_entry_t *next = c->next;
            free(c);
            c = next;
        }
    }
    free(children);

    /* read terminal bits and values from disk into temporary arrays (in builder node ID order) */
    uint8_t *temp_term = calloc((builder->n_nodes + 7) / 8, 1);
    int64_t *temp_vals = malloc(builder->n_vals * sizeof(int64_t));

    /* allocate final arrays (will be in LOUDS node order) */
    uint32_t term_bytes = (builder->n_nodes + 7) / 8;
    trie->term = calloc(term_bytes, 1);
    trie->vals = malloc(builder->n_vals * sizeof(int64_t));
    if (!trie->term || !trie->vals)
    {
        free(trie->term);
        free(trie->vals);
        free(trie->labels);
        free(trie->louds);
        free(trie);
        succinct_trie_builder_free(builder);
        return NULL;
    }

    /* read terminal bits into temp array (builder node ID order) */
    if (block_manager_cursor_init(&cursor, (block_manager_t *)builder->term_bm) == 0)
    {
        uint32_t idx = 0;
        while (block_manager_cursor_has_next(cursor) > 0 && idx < builder->n_nodes)
        {
            block_manager_block_t *block = block_manager_cursor_read(cursor);
            if (block)
            {
                if (*(uint8_t *)block->data) BIT_SET(temp_term, idx);
                block_manager_block_free(block);
            }
            idx++;
            block_manager_cursor_next(cursor);
        }
        block_manager_cursor_free(cursor);
    }

    /* reorder terminal bits from builder node ID order to LOUDS node order */
    uint32_t val_idx_in = 0; /* index for reading from temp_vals */
    for (uint32_t builder_node_id = 1; builder_node_id < builder->next_node_id; builder_node_id++)
    {
        uint32_t louds_node = node_id_to_louds[builder_node_id];
        if (louds_node > 0 && BIT_GET(temp_term, builder_node_id - 1))
        {
            BIT_SET(trie->term, louds_node - 1);
        }
    }

    /* read values into temp array (builder node ID order) */
    if (block_manager_cursor_init(&cursor, (block_manager_t *)builder->vals_bm) == 0)
    {
        uint32_t idx = 0;
        while (block_manager_cursor_has_next(cursor) > 0 && idx < builder->n_vals)
        {
            block_manager_block_t *block = block_manager_cursor_read(cursor);
            if (block)
            {
                temp_vals[idx++] = (int64_t)decode_uint64_le_compat((uint8_t *)block->data);
                block_manager_block_free(block);
            }
            block_manager_cursor_next(cursor);
        }
        block_manager_cursor_free(cursor);
    }

    /* reorder values from builder node ID order to LOUDS node order */
    val_idx_in = 0;

    for (uint32_t builder_node_id = 1; builder_node_id < builder->next_node_id; builder_node_id++)
    {
        if (BIT_GET(temp_term, builder_node_id - 1))
        {
            uint32_t louds_node = node_id_to_louds[builder_node_id];
            /* find the output position for this value */
            uint32_t louds_val_idx = rank1(trie->term, louds_node) - 1;
            trie->vals[louds_val_idx] = temp_vals[val_idx_in++];
        }
    }

    free(temp_term);
    free(temp_vals);
    free(node_id_to_louds);

    succinct_trie_builder_free(builder);
    return trie;
}

void succinct_trie_builder_free(succinct_trie_builder_t *builder)
{
    if (!builder) return;

    if (builder->labels_bm)
    {
        block_manager_t *bm = (block_manager_t *)builder->labels_bm;
        char path[MAX_FILE_PATH_LENGTH];
        strncpy(path, bm->file_path, MAX_FILE_PATH_LENGTH);
        block_manager_close(bm);
        unlink(path);
    }

    if (builder->parents_bm)
    {
        block_manager_t *bm = (block_manager_t *)builder->parents_bm;
        char path[MAX_FILE_PATH_LENGTH];
        strncpy(path, bm->file_path, MAX_FILE_PATH_LENGTH);
        block_manager_close(bm);
        unlink(path);
    }

    if (builder->child_ids_bm)
    {
        block_manager_t *bm = (block_manager_t *)builder->child_ids_bm;
        char path[MAX_FILE_PATH_LENGTH];
        strncpy(path, bm->file_path, MAX_FILE_PATH_LENGTH);
        block_manager_close(bm);
        unlink(path);
    }

    if (builder->term_bm)
    {
        block_manager_t *bm = (block_manager_t *)builder->term_bm;
        char path[MAX_FILE_PATH_LENGTH];
        strncpy(path, bm->file_path, MAX_FILE_PATH_LENGTH);
        block_manager_close(bm);
        unlink(path);
    }

    if (builder->vals_bm)
    {
        block_manager_t *bm = (block_manager_t *)builder->vals_bm;
        char path[MAX_FILE_PATH_LENGTH];
        strncpy(path, bm->file_path, MAX_FILE_PATH_LENGTH);
        block_manager_close(bm);
        unlink(path);
    }

    free(builder->prev_key);
    free(builder->path_stack);
    free(builder);
}

/*
 * find_first_terminal
 * @param trie the succinct trie
 * @param node the node to find the first terminal for
 * @param value pointer to store the value
 * @return 0 on success, -1 on failure
 */
static int find_first_terminal(const succinct_trie_t *trie, uint32_t node, int64_t *value)
{
    if (!trie || node == 0 || node > trie->n_nodes) return -1;

    /* check if this node is terminal */
    uint32_t node_idx = node - 1;
    if (BIT_GET(trie->term, node_idx))
    {
        uint32_t val_idx = rank1(trie->term, node_idx + 1) - 1;
        if (val_idx < trie->n_vals)
        {
            *value = trie->vals[val_idx];
            return 0;
        }
    }

    /* traverse children to find first terminal */
    uint32_t pos = get_children_start(trie, node);
    if (pos >= trie->louds_bits) return -1;

    while (pos < trie->louds_bits && BIT_GET(trie->louds, pos))
    {
        uint32_t edge_idx = rank1(trie->louds, pos + 1) - 2;
        if (edge_idx < trie->n_edges)
        {
            uint32_t child_node = trie->edge_child[edge_idx];
            if (find_first_terminal(trie, child_node, value) == 0)
            {
                return 0;
            }
        }
        pos++;
    }

    return -1;
}

int succinct_trie_prefix_get(const succinct_trie_t *trie, const uint8_t *prefix, size_t prefix_len,
                             int64_t *value)
{
    if (!trie || !prefix || !value) return -1;
    if (trie->n_nodes == 0) return -1;

    uint32_t node = 1; /* start at root */

    /* navigate to prefix */
    for (size_t depth = 0; depth < prefix_len; depth++)
    {
        uint32_t pos = get_children_start(trie, node);

        if (pos >= trie->louds_bits)
        {
            return -1;
        }
        bool found = false;

        while (pos < trie->louds_bits && BIT_GET(trie->louds, pos))
        {
            /* edge_idx rank1 counts all 1s including super-root, so subtract 2 (super-root + 1) */
            uint32_t edge_idx = rank1(trie->louds, pos + 1) - 2;
            if (edge_idx < trie->n_edges && trie->labels[edge_idx] == prefix[depth])
            {
                node = trie->edge_child[edge_idx];
                found = true;
                break;
            }
            pos++;
        }

        if (!found)
        {
            return -1;
        }
    }

    /* find first terminal in subtree */
    return find_first_terminal(trie, node, value);
}

void succinct_trie_free(succinct_trie_t *trie)
{
    if (!trie) return;
    free(trie->louds);
    free(trie->labels);
    free(trie->edge_child);
    free(trie->term);
    free(trie->vals);
    free(trie);
}

uint8_t *succinct_trie_serialize(const succinct_trie_t *trie, size_t *out_size)
{
    if (!trie || !out_size) return NULL;

    uint32_t louds_bytes = (trie->louds_bits + 7) / 8;
    uint32_t term_bytes = (trie->n_nodes + 7) / 8;

    *out_size = sizeof(uint32_t) * 4 + louds_bytes + trie->n_edges +
                trie->n_edges * sizeof(uint32_t) + term_bytes + trie->n_vals * sizeof(int64_t);

    uint8_t *buffer = malloc(*out_size);
    if (!buffer) return NULL;
    uint8_t *ptr = buffer;

    /* write louds_bits - little-endian */
    ptr[0] = (uint8_t)(trie->louds_bits & 0xFF);
    ptr[1] = (uint8_t)((trie->louds_bits >> 8) & 0xFF);
    ptr[2] = (uint8_t)((trie->louds_bits >> 16) & 0xFF);
    ptr[3] = (uint8_t)((trie->louds_bits >> 24) & 0xFF);
    ptr += sizeof(uint32_t);

    /* write n_edges - little-endian */
    ptr[0] = (uint8_t)(trie->n_edges & 0xFF);
    ptr[1] = (uint8_t)((trie->n_edges >> 8) & 0xFF);
    ptr[2] = (uint8_t)((trie->n_edges >> 16) & 0xFF);
    ptr[3] = (uint8_t)((trie->n_edges >> 24) & 0xFF);
    ptr += sizeof(uint32_t);

    /* write n_nodes - little-endian */
    ptr[0] = (uint8_t)(trie->n_nodes & 0xFF);
    ptr[1] = (uint8_t)((trie->n_nodes >> 8) & 0xFF);
    ptr[2] = (uint8_t)((trie->n_nodes >> 16) & 0xFF);
    ptr[3] = (uint8_t)((trie->n_nodes >> 24) & 0xFF);
    ptr += sizeof(uint32_t);

    /* write n_vals - little-endian */
    ptr[0] = (uint8_t)(trie->n_vals & 0xFF);
    ptr[1] = (uint8_t)((trie->n_vals >> 8) & 0xFF);
    ptr[2] = (uint8_t)((trie->n_vals >> 16) & 0xFF);
    ptr[3] = (uint8_t)((trie->n_vals >> 24) & 0xFF);
    ptr += sizeof(uint32_t);

    memcpy(ptr, trie->louds, louds_bytes);
    ptr += louds_bytes;

    if (trie->n_edges > 0)
    {
        memcpy(ptr, trie->labels, trie->n_edges);
        ptr += trie->n_edges;

        /* write edge_child array - little-endian */
        for (uint32_t i = 0; i < trie->n_edges; i++)
        {
            uint32_t val = trie->edge_child[i];
            ptr[0] = (uint8_t)(val & 0xFF);
            ptr[1] = (uint8_t)((val >> 8) & 0xFF);
            ptr[2] = (uint8_t)((val >> 16) & 0xFF);
            ptr[3] = (uint8_t)((val >> 24) & 0xFF);
            ptr += sizeof(uint32_t);
        }
    }

    memcpy(ptr, trie->term, term_bytes);
    ptr += term_bytes;

    if (trie->n_vals > 0)
    {
        /* write vals array - little-endian */
        for (uint32_t i = 0; i < trie->n_vals; i++)
        {
            int64_t val = trie->vals[i];
            uint64_t uval = (uint64_t)val;
            ptr[0] = (uint8_t)(uval & 0xFF);
            ptr[1] = (uint8_t)((uval >> 8) & 0xFF);
            ptr[2] = (uint8_t)((uval >> 16) & 0xFF);
            ptr[3] = (uint8_t)((uval >> 24) & 0xFF);
            ptr[4] = (uint8_t)((uval >> 32) & 0xFF);
            ptr[5] = (uint8_t)((uval >> 40) & 0xFF);
            ptr[6] = (uint8_t)((uval >> 48) & 0xFF);
            ptr[7] = (uint8_t)((uval >> 56) & 0xFF);
            ptr += sizeof(int64_t);
        }
    }

    return buffer;
}

succinct_trie_t *succinct_trie_deserialize(const uint8_t *data, size_t data_size)
{
    if (!data || data_size < sizeof(uint32_t) * 4) return NULL;

    const uint8_t *ptr = data;
    succinct_trie_t *trie = calloc(1, sizeof(succinct_trie_t));
    if (!trie) return NULL;

    /* read louds_bits - little-endian */
    trie->louds_bits = ((uint32_t)ptr[0]) | ((uint32_t)ptr[1] << 8) | ((uint32_t)ptr[2] << 16) |
                       ((uint32_t)ptr[3] << 24);
    ptr += sizeof(uint32_t);

    /* read n_edges - little-endian */
    trie->n_edges = ((uint32_t)ptr[0]) | ((uint32_t)ptr[1] << 8) | ((uint32_t)ptr[2] << 16) |
                    ((uint32_t)ptr[3] << 24);
    ptr += sizeof(uint32_t);

    /* read n_nodes - little-endian */
    trie->n_nodes = ((uint32_t)ptr[0]) | ((uint32_t)ptr[1] << 8) | ((uint32_t)ptr[2] << 16) |
                    ((uint32_t)ptr[3] << 24);
    ptr += sizeof(uint32_t);

    /* read n_vals - little-endian */
    trie->n_vals = ((uint32_t)ptr[0]) | ((uint32_t)ptr[1] << 8) | ((uint32_t)ptr[2] << 16) |
                   ((uint32_t)ptr[3] << 24);
    ptr += sizeof(uint32_t);

    uint32_t louds_bytes = (trie->louds_bits + 7) / 8;
    uint32_t term_bytes = (trie->n_nodes + 7) / 8;

    trie->louds = malloc(louds_bytes);
    if (!trie->louds)
    {
        free(trie);
        return NULL;
    }
    memcpy(trie->louds, ptr, louds_bytes);
    ptr += louds_bytes;

    if (trie->n_edges > 0)
    {
        trie->labels = malloc(trie->n_edges);
        if (!trie->labels)
        {
            free(trie->louds);
            free(trie);
            return NULL;
        }
        memcpy(trie->labels, ptr, trie->n_edges);
        ptr += trie->n_edges;

        trie->edge_child = malloc(trie->n_edges * sizeof(uint32_t));
        if (!trie->edge_child)
        {
            free(trie->labels);
            free(trie->louds);
            free(trie);
            return NULL;
        }

        /* read edge_child array - little-endian */
        for (uint32_t i = 0; i < trie->n_edges; i++)
        {
            trie->edge_child[i] = ((uint32_t)ptr[0]) | ((uint32_t)ptr[1] << 8) |
                                  ((uint32_t)ptr[2] << 16) | ((uint32_t)ptr[3] << 24);
            ptr += sizeof(uint32_t);
        }
    }
    else
    {
        trie->labels = NULL;
        trie->edge_child = NULL;
    }

    trie->term = malloc(term_bytes);
    if (!trie->term)
    {
        free(trie->labels);
        free(trie->louds);
        free(trie);
        return NULL;
    }
    memcpy(trie->term, ptr, term_bytes);
    ptr += term_bytes;

    if (trie->n_vals > 0)
    {
        trie->vals = malloc(trie->n_vals * sizeof(int64_t));
        if (!trie->vals)
        {
            free(trie->term);
            free(trie->labels);
            free(trie->louds);
            free(trie);
            return NULL;
        }

        /* read vals array - little-endian */
        for (uint32_t i = 0; i < trie->n_vals; i++)
        {
            uint64_t uval = ((uint64_t)ptr[0]) | ((uint64_t)ptr[1] << 8) |
                            ((uint64_t)ptr[2] << 16) | ((uint64_t)ptr[3] << 24) |
                            ((uint64_t)ptr[4] << 32) | ((uint64_t)ptr[5] << 40) |
                            ((uint64_t)ptr[6] << 48) | ((uint64_t)ptr[7] << 56);
            trie->vals[i] = (int64_t)uval;
            ptr += sizeof(int64_t);
        }
    }
    else
    {
        trie->vals = NULL;
    }

    trie->comparator = succinct_trie_comparator_memcmp;
    trie->comparator_ctx = NULL;

    return trie;
}

size_t succinct_trie_get_size(const succinct_trie_t *trie)
{
    if (!trie) return 0;

    uint32_t louds_bytes = (trie->louds_bits + 7) / 8;
    uint32_t term_bytes = (trie->n_nodes + 7) / 8;

    return sizeof(uint32_t) * 4 + louds_bytes + trie->n_edges + trie->n_edges * sizeof(uint32_t) +
           term_bytes + trie->n_vals * sizeof(int64_t);
}
