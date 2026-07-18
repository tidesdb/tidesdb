/**
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
#include "blocked_index.h"

#include <stdlib.h>
#include <string.h>

/* directory blob layout, all little-endian
 *   magic (4) | version (4) | partition_count (4)
 *   then partition_count records of
 *     leaf_offset (8) | leaf_size (4) | block_count (4) | first_key_len (4) | first_key bytes
 *
 * leaf blob layout, all little-endian. an offset table lets the reader binary-search the
 * variable-length records in place, with no per-lookup allocation.
 *   block_count (4) | offsets[block_count] (4 each, byte offset of the record within the leaf)
 *   then block_count records of
 *     first_key_len (4) | first_key bytes | block_offset (8)
 * records are in ascending first-key order. */
#define BI_DIR_MAGIC   0x49424254u /* "TBBI" little-endian */
#define BI_DIR_VERSION 1u
/* magic + version + partition_count */
#define BI_DIR_HEADER_BYTES (3 * sizeof(uint32_t))
/* per-record bytes before the variable first_key -- leaf_offset + leaf_size + block_count +
 * first_key_len */
#define BI_DIR_ENTRY_FIXED (sizeof(uint64_t) + 3 * sizeof(uint32_t))
/* per-leaf-record bytes around the variable key -- first_key_len + block_offset */
#define BI_LEAF_REC_FIXED (sizeof(uint32_t) + sizeof(uint64_t))

/* little-endian byte codecs for the directory and leaves, endian-canonical so an index built on one
 * host reads back identically on another */
static void bi_put_u32le(uint8_t *p, uint32_t v)
{
    for (size_t i = 0; i < sizeof(uint32_t); i++) p[i] = (uint8_t)(v >> (8 * i));
}

static void bi_put_u64le(uint8_t *p, uint64_t v)
{
    for (size_t i = 0; i < sizeof(uint64_t); i++) p[i] = (uint8_t)(v >> (8 * i));
}

static uint32_t bi_get_u32le(const uint8_t *p)
{
    uint32_t v = 0;
    for (size_t i = 0; i < sizeof(uint32_t); i++) v |= (uint32_t)p[i] << (8 * i);
    return v;
}

static uint64_t bi_get_u64le(const uint8_t *p)
{
    uint64_t v = 0;
    for (size_t i = 0; i < sizeof(uint64_t); i++) v |= (uint64_t)p[i] << (8 * i);
    return v;
}

/* one block as accumulated by the builder for the leaf it is filling */
typedef struct
{
    uint8_t *first_key; /* owned copy */
    uint32_t first_key_len;
    uint64_t block_offset;
} bi_block_t;

/* one partition (leaf) as recorded in the directory */
typedef struct
{
    uint8_t *leaf_blob; /* serialized leaf, held until finish writes it (builder only) */
    uint64_t leaf_offset;
    uint32_t leaf_size;
    uint32_t block_count;
    uint64_t base;      /* ordinal of this partition's first block, filled at reader open */
    uint8_t *first_key; /* owned copy of the partition's first block first-key */
    uint32_t first_key_len;
} bi_part_t;

struct blocked_index_builder
{
    uint32_t blocks_per_partition;
    blocked_index_write_fn write_fn;
    void *write_ctx;

    bi_block_t *cur; /* blocks of the leaf being filled */
    uint32_t cur_count;
    uint32_t cur_cap;

    bi_part_t *parts;
    size_t num_parts;
    size_t cap_parts;

    uint64_t total_blocks;
    int failed; /* sticky -- a write or allocation failure poisons the build */
};

struct blocked_index_reader
{
    blocked_index_comparator_fn cmp;
    void *cmp_ctx;
    blocked_index_fetch_fn fetch_fn;
    blocked_index_release_fn release_fn;
    void *cb_ctx;

    bi_part_t *parts; /* ascending first-key order; first_key owned */
    uint32_t num_parts;
    size_t resident_bytes;
};

static void bi_parts_free(bi_part_t *parts, size_t n)
{
    if (!parts) return;
    for (size_t i = 0; i < n; i++)
    {
        free(parts[i].first_key);
        free(parts[i].leaf_blob);
    }
    free(parts);
}

static void bi_cur_free(blocked_index_builder_t *b)
{
    for (uint32_t i = 0; i < b->cur_count; i++) free(b->cur[i].first_key);
    b->cur_count = 0;
}

int blocked_index_builder_new(blocked_index_builder_t **out, uint32_t blocks_per_partition,
                              blocked_index_write_fn write_fn, void *write_ctx)
{
    if (!out || !write_fn) return -1;
    if (blocks_per_partition == 0)
        blocks_per_partition = TDB_BLOCKED_INDEX_DEFAULT_BLOCKS_PER_PARTITION;

    blocked_index_builder_t *b = calloc(1, sizeof(*b));
    if (!b) return -1;
    b->blocks_per_partition = blocks_per_partition;
    b->write_fn = write_fn;
    b->write_ctx = write_ctx;
    *out = b;
    return 0;
}

/* serialize the current leaf and record the partition, holding its blob until finish writes it
 * after the sstable's klog data. a no-op when the leaf is empty. takes ownership of the first
 * block's first-key for the directory entry. */
static int bi_seal_leaf(blocked_index_builder_t *b)
{
    if (b->cur_count == 0) return 0;

    /* leaf header is a block_count then an offset-table slot per record, both u32 */
    const size_t header = sizeof(uint32_t) + (size_t)sizeof(uint32_t) * b->cur_count;
    size_t body = 0;
    for (uint32_t i = 0; i < b->cur_count; i++) body += BI_LEAF_REC_FIXED + b->cur[i].first_key_len;
    size_t leaf_size = header + body;
    if (leaf_size > UINT32_MAX) return -1;

    uint8_t *leaf = malloc(leaf_size);
    if (!leaf) return -1;

    bi_put_u32le(leaf, b->cur_count);
    uint8_t *rec = leaf + header; /* records begin after the offset table */
    for (uint32_t i = 0; i < b->cur_count; i++)
    {
        /* offset of record i in the offset table */
        bi_put_u32le(leaf + sizeof(uint32_t) + (size_t)sizeof(uint32_t) * i,
                     (uint32_t)(rec - leaf));
        bi_put_u32le(rec, b->cur[i].first_key_len);
        rec += sizeof(uint32_t);
        memcpy(rec, b->cur[i].first_key, b->cur[i].first_key_len);
        rec += b->cur[i].first_key_len;
        bi_put_u64le(rec, b->cur[i].block_offset);
        rec += sizeof(uint64_t);
    }

    if (b->num_parts == b->cap_parts)
    {
        size_t ncap = b->cap_parts ? b->cap_parts * 2 : 16;
        bi_part_t *np = realloc(b->parts, ncap * sizeof(*np));
        if (!np)
        {
            free(leaf);
            return -1;
        }
        b->parts = np;
        b->cap_parts = ncap;
    }

    bi_part_t *e = &b->parts[b->num_parts++];
    e->leaf_blob = leaf; /* written at finish */
    e->leaf_offset = 0;  /* filled at finish */
    e->leaf_size = (uint32_t)leaf_size;
    e->block_count = b->cur_count;
    e->base = 0;
    e->first_key = b->cur[0].first_key; /* ownership transferred */
    e->first_key_len = b->cur[0].first_key_len;
    b->cur[0].first_key = NULL;

    bi_cur_free(b);
    return 0;
}

int blocked_index_builder_add(blocked_index_builder_t *b, const uint8_t *first_key,
                              size_t first_key_size, uint64_t block_offset)
{
    if (!b) return 0; /* a NULL builder means the index is disabled -- adding is a no-op */
    if (!first_key || first_key_size == 0) return -1;
    if (b->failed) return -1;

    if (b->cur_count == b->cur_cap)
    {
        uint32_t ncap = b->cur_cap ? b->cur_cap * 2 : 64;
        if (ncap > b->blocks_per_partition) ncap = b->blocks_per_partition;
        bi_block_t *nc = realloc(b->cur, (size_t)ncap * sizeof(*nc));
        if (!nc)
        {
            b->failed = 1;
            return -1;
        }
        b->cur = nc;
        b->cur_cap = ncap;
    }

    uint8_t *kc = malloc(first_key_size);
    if (!kc)
    {
        b->failed = 1;
        return -1;
    }
    memcpy(kc, first_key, first_key_size);
    b->cur[b->cur_count].first_key = kc;
    b->cur[b->cur_count].first_key_len = (uint32_t)first_key_size;
    b->cur[b->cur_count].block_offset = block_offset;
    b->cur_count++;
    b->total_blocks++;

    if (b->cur_count >= b->blocks_per_partition)
    {
        if (bi_seal_leaf(b) != 0)
        {
            b->failed = 1;
            return -1;
        }
    }
    return 0;
}

/* serialized directory size for the recorded partitions */
static size_t bi_dir_size(const blocked_index_builder_t *b)
{
    size_t total = BI_DIR_HEADER_BYTES;
    for (size_t i = 0; i < b->num_parts; i++)
        total += BI_DIR_ENTRY_FIXED + b->parts[i].first_key_len;
    return total;
}

int blocked_index_builder_finish(blocked_index_builder_t *b, uint64_t *out_dir_offset,
                                 uint32_t *out_dir_size, uint64_t *out_total_blocks)
{
    if (!b || !out_dir_offset || !out_dir_size) return -1;
    if (b->failed) return -1;

    if (bi_seal_leaf(b) != 0)
    {
        b->failed = 1;
        return -1;
    }

    /* write every buffered leaf now -- the caller invokes finish from the sstable footer, after the
     * klog data blocks, so these land contiguously past the data and their offsets are final */
    for (size_t i = 0; i < b->num_parts; i++)
    {
        uint64_t offset = 0;
        int rc = b->write_fn(b->write_ctx, b->parts[i].leaf_blob, b->parts[i].leaf_size, &offset);
        if (rc != 0)
        {
            b->failed = 1;
            return rc;
        }
        b->parts[i].leaf_offset = offset;
        free(b->parts[i].leaf_blob);
        b->parts[i].leaf_blob = NULL;
    }

    size_t dir_size = bi_dir_size(b);
    if (dir_size > UINT32_MAX) return -1;
    uint8_t *dir = malloc(dir_size);
    if (!dir) return -1;

    uint8_t *p = dir;
    bi_put_u32le(p, BI_DIR_MAGIC);
    p += sizeof(uint32_t);
    bi_put_u32le(p, BI_DIR_VERSION);
    p += sizeof(uint32_t);
    bi_put_u32le(p, (uint32_t)b->num_parts);
    p += sizeof(uint32_t);
    for (size_t i = 0; i < b->num_parts; i++)
    {
        const bi_part_t *e = &b->parts[i];
        bi_put_u64le(p, e->leaf_offset);
        p += sizeof(uint64_t);
        bi_put_u32le(p, e->leaf_size);
        p += sizeof(uint32_t);
        bi_put_u32le(p, e->block_count);
        p += sizeof(uint32_t);
        bi_put_u32le(p, e->first_key_len);
        p += sizeof(uint32_t);
        memcpy(p, e->first_key, e->first_key_len);
        p += e->first_key_len;
    }

    uint64_t offset = 0;
    int rc = b->write_fn(b->write_ctx, dir, dir_size, &offset);
    free(dir);
    if (rc != 0) return rc;

    *out_dir_offset = offset;
    *out_dir_size = (uint32_t)dir_size;
    if (out_total_blocks) *out_total_blocks = b->total_blocks;
    return 0;
}

void blocked_index_builder_free(blocked_index_builder_t *b)
{
    if (!b) return;
    bi_cur_free(b);
    free(b->cur);
    bi_parts_free(b->parts, b->num_parts);
    free(b);
}

/* parse a directory blob into an ascending array of partitions and fill each partition's base
 * ordinal from the running block total. returns 0 on success. */
static int bi_parse_dir(const uint8_t *data, size_t len, bi_part_t **out_parts, uint32_t *out_n,
                        size_t *out_resident)
{
    if (len < BI_DIR_HEADER_BYTES) return -1;
    if (bi_get_u32le(data) != BI_DIR_MAGIC) return -1;
    if (bi_get_u32le(data + sizeof(uint32_t)) != BI_DIR_VERSION) return -1;
    uint32_t n = bi_get_u32le(data + 2 * sizeof(uint32_t));

    if (n == 0)
    {
        *out_parts = NULL;
        *out_n = 0;
        *out_resident = 0;
        return 0;
    }

    bi_part_t *parts = calloc(n, sizeof(*parts));
    if (!parts) return -1;

    size_t resident = n * sizeof(*parts);
    uint64_t base = 0;
    const uint8_t *p = data + BI_DIR_HEADER_BYTES;
    const uint8_t *end = data + len;
    for (uint32_t i = 0; i < n; i++)
    {
        if ((size_t)(end - p) < BI_DIR_ENTRY_FIXED)
        {
            bi_parts_free(parts, i);
            return -1;
        }
        parts[i].leaf_offset = bi_get_u64le(p);
        p += sizeof(uint64_t);
        parts[i].leaf_size = bi_get_u32le(p);
        p += sizeof(uint32_t);
        parts[i].block_count = bi_get_u32le(p);
        p += sizeof(uint32_t);
        parts[i].first_key_len = bi_get_u32le(p);
        p += sizeof(uint32_t);
        if (parts[i].first_key_len == 0 || (size_t)(end - p) < parts[i].first_key_len)
        {
            bi_parts_free(parts, i);
            return -1;
        }
        parts[i].first_key = malloc(parts[i].first_key_len);
        if (!parts[i].first_key)
        {
            bi_parts_free(parts, i);
            return -1;
        }
        memcpy(parts[i].first_key, p, parts[i].first_key_len);
        p += parts[i].first_key_len;
        parts[i].base = base;
        base += parts[i].block_count;
        resident += parts[i].first_key_len;
    }

    *out_parts = parts;
    *out_n = n;
    *out_resident = resident;
    return 0;
}

int blocked_index_reader_open(blocked_index_reader_t **out, uint64_t dir_offset, uint32_t dir_size,
                              blocked_index_comparator_fn cmp, void *cmp_ctx,
                              blocked_index_fetch_fn fetch_fn, blocked_index_release_fn release_fn,
                              void *cb_ctx)
{
    if (!out || !cmp || !fetch_fn || dir_size == 0) return -1;

    const uint8_t *dir_data = NULL;
    void *pin = NULL;
    if (fetch_fn(cb_ctx, dir_offset, dir_size, &dir_data, &pin) != 0 || !dir_data) return -1;

    bi_part_t *parts = NULL;
    uint32_t n = 0;
    size_t resident = 0;
    int rc = bi_parse_dir(dir_data, dir_size, &parts, &n, &resident);
    if (pin && release_fn) release_fn(cb_ctx, pin);
    if (rc != 0) return -1;

    blocked_index_reader_t *r = calloc(1, sizeof(*r));
    if (!r)
    {
        bi_parts_free(parts, n);
        return -1;
    }
    r->cmp = cmp;
    r->cmp_ctx = cmp_ctx;
    r->fetch_fn = fetch_fn;
    r->release_fn = release_fn;
    r->cb_ctx = cb_ctx;
    r->parts = parts;
    r->num_parts = n;
    r->resident_bytes = sizeof(*r) + resident;
    *out = r;
    return 0;
}

/* index of the partition whose range covers key, or -1 if key sorts before the first partition */
static int64_t bi_route(const blocked_index_reader_t *r, const uint8_t *key, size_t key_size)
{
    int64_t lo = 0, hi = (int64_t)r->num_parts - 1, res = -1;
    while (lo <= hi)
    {
        int64_t mid = lo + (hi - lo) / 2;
        int c =
            r->cmp(r->parts[mid].first_key, r->parts[mid].first_key_len, key, key_size, r->cmp_ctx);
        if (c <= 0)
        {
            res = mid;
            lo = mid + 1;
        }
        else
        {
            hi = mid - 1;
        }
    }
    return res;
}

/* locate record i in a leaf blob, validating every offset against the blob length. sets the key and
 * block offset for a valid record. returns 0 on success, -1 on a malformed leaf. */
static int bi_leaf_record(const uint8_t *leaf, uint32_t leaf_size, uint32_t block_count, uint32_t i,
                          const uint8_t **out_key, uint32_t *out_key_len,
                          uint64_t *out_block_offset)
{
    size_t table_end = sizeof(uint32_t) + (size_t)sizeof(uint32_t) * block_count;
    if (table_end > leaf_size) return -1;
    uint32_t rec_off = bi_get_u32le(leaf + sizeof(uint32_t) + (size_t)sizeof(uint32_t) * i);
    if (rec_off < table_end || (size_t)rec_off + sizeof(uint32_t) > leaf_size) return -1;
    uint32_t klen = bi_get_u32le(leaf + rec_off);
    size_t need = (size_t)rec_off + BI_LEAF_REC_FIXED + klen;
    if (klen == 0 || need > leaf_size) return -1;
    *out_key = leaf + rec_off + sizeof(uint32_t);
    *out_key_len = klen;
    *out_block_offset = bi_get_u64le(leaf + rec_off + sizeof(uint32_t) + klen);
    return 0;
}

int blocked_index_reader_find(blocked_index_reader_t *r, const uint8_t *key, size_t key_size,
                              uint64_t *out_block_offset, uint64_t *out_block_ordinal)
{
    if (!r || !key || key_size == 0 || !out_block_offset) return -1;
    if (r->num_parts == 0) return 0;

    int64_t pi = bi_route(r, key, key_size);
    if (pi < 0) return 0; /* sorts before every block */
    const bi_part_t *part = &r->parts[pi];

    const uint8_t *leaf = NULL;
    void *pin = NULL;
    if (r->fetch_fn(r->cb_ctx, part->leaf_offset, part->leaf_size, &leaf, &pin) != 0 || !leaf)
        return -1;

    int ret = -1;
    if (part->leaf_size >= sizeof(uint32_t))
    {
        uint32_t block_count = bi_get_u32le(leaf);
        if (block_count == part->block_count && block_count > 0)
        {
            /* rightmost record whose first-key is <= key */
            int64_t lo = 0, hi = (int64_t)block_count - 1, res = -1;
            int ok = 1;
            while (lo <= hi)
            {
                int64_t mid = lo + (hi - lo) / 2;
                const uint8_t *rk = NULL;
                uint32_t rklen = 0;
                uint64_t roff = 0;
                if (bi_leaf_record(leaf, part->leaf_size, block_count, (uint32_t)mid, &rk, &rklen,
                                   &roff) != 0)
                {
                    ok = 0;
                    break;
                }
                if (r->cmp(rk, rklen, key, key_size, r->cmp_ctx) <= 0)
                {
                    res = mid;
                    lo = mid + 1;
                }
                else
                {
                    hi = mid - 1;
                }
            }
            if (ok && res >= 0)
            {
                const uint8_t *rk = NULL;
                uint32_t rklen = 0;
                uint64_t roff = 0;
                if (bi_leaf_record(leaf, part->leaf_size, block_count, (uint32_t)res, &rk, &rklen,
                                   &roff) == 0)
                {
                    *out_block_offset = roff;
                    if (out_block_ordinal) *out_block_ordinal = part->base + (uint64_t)res;
                    ret = 1;
                }
            }
            else if (ok && res < 0)
            {
                ret = 0; /* routing guarantees this cannot normally happen */
            }
        }
    }

    if (pin && r->release_fn) r->release_fn(r->cb_ctx, pin);
    return ret;
}

size_t blocked_index_reader_resident_bytes(const blocked_index_reader_t *r)
{
    return r ? r->resident_bytes : 0;
}

void blocked_index_reader_free(blocked_index_reader_t *r)
{
    if (!r) return;
    bi_parts_free(r->parts, r->num_parts);
    free(r);
}
