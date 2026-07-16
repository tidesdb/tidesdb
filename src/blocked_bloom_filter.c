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
#include "blocked_bloom_filter.h"

#include <stdlib.h>
#include <string.h>

/* directory blob layout, all little-endian
 *   magic (4) | version (4) | partition_count (4)
 *   then partition_count records of
 *     disk_offset (8) | blob_size (4) | entry_count (4) | first_key_len (4) | first_key bytes
 * the partition records are in build (ascending key) order, so the reader binary-searches them
 * directly. */
#define BBF_DIR_MAGIC   0x46424254u /* "TBBF" little-endian */
#define BBF_DIR_VERSION 1u
/* magic + version + partition_count */
#define BBF_DIR_HEADER_BYTES (3 * sizeof(uint32_t))
/* per-record bytes before the variable first_key: disk_offset + blob_size + entry_count +
 * first_key_len */
#define BBF_DIR_ENTRY_FIXED (sizeof(uint64_t) + 3 * sizeof(uint32_t))

/* little-endian byte codecs for the directory, endian-canonical so a filter built on one host
 * reads back identically on another */
static void bbf_put_u32le(uint8_t *p, uint32_t v)
{
    for (size_t i = 0; i < sizeof(uint32_t); i++) p[i] = (uint8_t)(v >> (8 * i));
}

static void bbf_put_u64le(uint8_t *p, uint64_t v)
{
    for (size_t i = 0; i < sizeof(uint64_t); i++) p[i] = (uint8_t)(v >> (8 * i));
}

static uint32_t bbf_get_u32le(const uint8_t *p)
{
    uint32_t v = 0;
    for (size_t i = 0; i < sizeof(uint32_t); i++) v |= (uint32_t)p[i] << (8 * i);
    return v;
}

static uint64_t bbf_get_u64le(const uint8_t *p)
{
    uint64_t v = 0;
    for (size_t i = 0; i < sizeof(uint64_t); i++) v |= (uint64_t)p[i] << (8 * i);
    return v;
}

/* one partition as tracked by the builder and reconstructed by the reader */
typedef struct
{
    uint8_t *blob;      /* serialized partition, held until finish writes it (builder only) */
    uint64_t offset;    /* where the partition blob was written, set at finish */
    uint32_t size;      /* partition blob length */
    uint32_t count;     /* keys in the partition */
    uint8_t *first_key; /* owned copy of the partition's first key */
    uint32_t first_key_len;
} bbf_partition_t;

struct blocked_bloom_builder
{
    double fpr;
    uint32_t partition_entries;
    blocked_bloom_write_fn write_fn;
    void *write_ctx;

    bloom_filter_t *current; /* partition being filled, NULL between partitions */
    uint32_t current_count;
    uint8_t *current_first_key;
    uint32_t current_first_key_len;

    bbf_partition_t *parts;
    size_t num_parts;
    size_t cap_parts;

    uint64_t total_entries;
    int failed; /* sticky -- a write or allocation failure poisons the build */
};

struct blocked_bloom_reader
{
    blocked_bloom_comparator_fn cmp;
    void *cmp_ctx;
    blocked_bloom_fetch_fn fetch_fn;
    blocked_bloom_release_fn release_fn;
    void *cb_ctx;

    bbf_partition_t *parts; /* ascending key order; first_key owned */
    uint32_t num_parts;
    size_t resident_bytes;
};

/* free a partition array and the first-key copies it owns */
static void bbf_partitions_free(bbf_partition_t *parts, size_t n)
{
    if (!parts) return;
    for (size_t i = 0; i < n; i++)
    {
        free(parts[i].first_key);
        free(parts[i].blob);
    }
    free(parts);
}

int blocked_bloom_builder_new(blocked_bloom_builder_t **out, double fpr, uint32_t partition_entries,
                              blocked_bloom_write_fn write_fn, void *write_ctx)
{
    if (!out || !write_fn || !(fpr > 0.0 && fpr < 1.0)) return -1;
    if (partition_entries == 0) partition_entries = TDB_BLOCKED_BLOOM_DEFAULT_PARTITION_ENTRIES;

    blocked_bloom_builder_t *b = calloc(1, sizeof(*b));
    if (!b) return -1;

    b->fpr = fpr;
    b->partition_entries = partition_entries;
    b->write_fn = write_fn;
    b->write_ctx = write_ctx;
    *out = b;
    return 0;
}

/* serialize the current partition and record it, holding its blob until finish writes it after the
 * sstable's klog data. takes ownership of current_first_key on success. a no-op when no partition
 * is open. */
static int bbf_seal_current(blocked_bloom_builder_t *b)
{
    if (!b->current) return 0;

    size_t blob_size = 0;
    uint8_t *blob = bloom_filter_serialize(b->current, &blob_size);
    if (!blob || blob_size == 0 || blob_size > UINT32_MAX)
    {
        free(blob);
        return -1;
    }

    if (b->num_parts == b->cap_parts)
    {
        size_t ncap = b->cap_parts ? b->cap_parts * 2 : 16;
        bbf_partition_t *np = realloc(b->parts, ncap * sizeof(*np));
        if (!np)
        {
            free(blob);
            return -1;
        }
        b->parts = np;
        b->cap_parts = ncap;
    }

    bbf_partition_t *e = &b->parts[b->num_parts++];
    e->blob = blob; /* written at finish */
    e->offset = 0;  /* filled at finish */
    e->size = (uint32_t)blob_size;
    e->count = b->current_count;
    e->first_key = b->current_first_key; /* ownership transferred */
    e->first_key_len = b->current_first_key_len;

    b->current_first_key = NULL;
    b->current_first_key_len = 0;
    bloom_filter_free(b->current);
    b->current = NULL;
    b->current_count = 0;
    return 0;
}

int blocked_bloom_builder_add(blocked_bloom_builder_t *b, const uint8_t *key, size_t key_size)
{
    if (!b) return 0; /* a NULL builder means the filter is disabled -- adding is a no-op */
    if (!key || key_size == 0) return -1;
    if (b->failed) return -1;

    if (!b->current)
    {
        if (bloom_filter_new(&b->current, b->fpr, (int)b->partition_entries) != 0)
        {
            b->failed = 1;
            return -1;
        }
        b->current_first_key = malloc(key_size);
        if (!b->current_first_key)
        {
            bloom_filter_free(b->current);
            b->current = NULL;
            b->failed = 1;
            return -1;
        }
        memcpy(b->current_first_key, key, key_size);
        b->current_first_key_len = (uint32_t)key_size;
        b->current_count = 0;
    }

    bloom_filter_add(b->current, key, key_size);
    b->current_count++;
    b->total_entries++;

    if (b->current_count >= b->partition_entries)
    {
        if (bbf_seal_current(b) != 0)
        {
            b->failed = 1;
            return -1;
        }
    }
    return 0;
}

/* serialized directory size for the recorded partitions */
static size_t bbf_dir_size(const blocked_bloom_builder_t *b)
{
    size_t total = BBF_DIR_HEADER_BYTES;
    for (size_t i = 0; i < b->num_parts; i++)
        total += BBF_DIR_ENTRY_FIXED + b->parts[i].first_key_len;
    return total;
}

int blocked_bloom_builder_finish(blocked_bloom_builder_t *b, uint64_t *out_dir_offset,
                                 uint32_t *out_dir_size, uint64_t *out_total_entries)
{
    if (!b || !out_dir_offset || !out_dir_size) return -1;
    if (b->failed) return -1;

    if (bbf_seal_current(b) != 0)
    {
        b->failed = 1;
        return -1;
    }

    /* write every buffered partition now -- the caller invokes finish from the sstable footer,
     * after the klog data blocks, so these land contiguously past the data and their offsets are
     * final */
    for (size_t i = 0; i < b->num_parts; i++)
    {
        uint64_t offset = 0;
        int rc = b->write_fn(b->write_ctx, b->parts[i].blob, b->parts[i].size, &offset);
        if (rc != 0)
        {
            b->failed = 1;
            return rc;
        }
        b->parts[i].offset = offset;
        free(b->parts[i].blob);
        b->parts[i].blob = NULL;
    }

    size_t dir_size = bbf_dir_size(b);
    if (dir_size > UINT32_MAX) return -1;
    uint8_t *dir = malloc(dir_size);
    if (!dir) return -1;

    uint8_t *p = dir;
    bbf_put_u32le(p, BBF_DIR_MAGIC);
    p += sizeof(uint32_t);
    bbf_put_u32le(p, BBF_DIR_VERSION);
    p += sizeof(uint32_t);
    bbf_put_u32le(p, (uint32_t)b->num_parts);
    p += sizeof(uint32_t);
    for (size_t i = 0; i < b->num_parts; i++)
    {
        const bbf_partition_t *e = &b->parts[i];
        bbf_put_u64le(p, e->offset);
        p += sizeof(uint64_t);
        bbf_put_u32le(p, e->size);
        p += sizeof(uint32_t);
        bbf_put_u32le(p, e->count);
        p += sizeof(uint32_t);
        bbf_put_u32le(p, e->first_key_len);
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
    if (out_total_entries) *out_total_entries = b->total_entries;
    return 0;
}

void blocked_bloom_builder_free(blocked_bloom_builder_t *b)
{
    if (!b) return;
    if (b->current) bloom_filter_free(b->current);
    free(b->current_first_key);
    bbf_partitions_free(b->parts, b->num_parts);
    free(b);
}

/* parse a directory blob into an ascending array of partitions. returns 0 on success. */
static int bbf_parse_dir(const uint8_t *data, size_t len, bbf_partition_t **out_parts,
                         uint32_t *out_n, size_t *out_resident)
{
    if (len < BBF_DIR_HEADER_BYTES) return -1;
    if (bbf_get_u32le(data) != BBF_DIR_MAGIC) return -1;
    if (bbf_get_u32le(data + sizeof(uint32_t)) != BBF_DIR_VERSION) return -1;
    uint32_t n = bbf_get_u32le(data + 2 * sizeof(uint32_t));

    if (n == 0)
    {
        *out_parts = NULL;
        *out_n = 0;
        *out_resident = 0;
        return 0;
    }

    bbf_partition_t *parts = calloc(n, sizeof(*parts));
    if (!parts) return -1;

    size_t resident = n * sizeof(*parts);
    const uint8_t *p = data + BBF_DIR_HEADER_BYTES;
    const uint8_t *end = data + len;
    for (uint32_t i = 0; i < n; i++)
    {
        if ((size_t)(end - p) < BBF_DIR_ENTRY_FIXED)
        {
            bbf_partitions_free(parts, i);
            return -1;
        }
        parts[i].offset = bbf_get_u64le(p);
        p += sizeof(uint64_t);
        parts[i].size = bbf_get_u32le(p);
        p += sizeof(uint32_t);
        parts[i].count = bbf_get_u32le(p);
        p += sizeof(uint32_t);
        parts[i].first_key_len = bbf_get_u32le(p);
        p += sizeof(uint32_t);
        if (parts[i].first_key_len == 0 || (size_t)(end - p) < parts[i].first_key_len)
        {
            bbf_partitions_free(parts, i);
            return -1;
        }
        parts[i].first_key = malloc(parts[i].first_key_len);
        if (!parts[i].first_key)
        {
            bbf_partitions_free(parts, i);
            return -1;
        }
        memcpy(parts[i].first_key, p, parts[i].first_key_len);
        p += parts[i].first_key_len;
        resident += parts[i].first_key_len;
    }

    *out_parts = parts;
    *out_n = n;
    *out_resident = resident;
    return 0;
}

int blocked_bloom_reader_open(blocked_bloom_reader_t **out, uint64_t dir_offset, uint32_t dir_size,
                              blocked_bloom_comparator_fn cmp, void *cmp_ctx,
                              blocked_bloom_fetch_fn fetch_fn, blocked_bloom_release_fn release_fn,
                              void *cb_ctx)
{
    if (!out || !cmp || !fetch_fn || dir_size == 0) return -1;

    const uint8_t *dir_data = NULL;
    void *pin = NULL;
    if (fetch_fn(cb_ctx, dir_offset, dir_size, &dir_data, &pin) != 0 || !dir_data) return -1;

    bbf_partition_t *parts = NULL;
    uint32_t n = 0;
    size_t resident = 0;
    int rc = bbf_parse_dir(dir_data, dir_size, &parts, &n, &resident);
    if (pin && release_fn) release_fn(cb_ctx, pin);
    if (rc != 0) return -1;

    blocked_bloom_reader_t *r = calloc(1, sizeof(*r));
    if (!r)
    {
        bbf_partitions_free(parts, n);
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

/* index of the partition whose range covers key, or -1 if key sorts before the first partition.
 * partitions are ascending, so this is the rightmost first_key <= key. */
static int64_t bbf_route(const blocked_bloom_reader_t *r, const uint8_t *key, size_t key_size)
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

int blocked_bloom_reader_maybe_contains(blocked_bloom_reader_t *r, const uint8_t *key,
                                        size_t key_size)
{
    if (!r || !key || key_size == 0) return -1;
    if (r->num_parts == 0) return 1; /* no filter -- safe answer is may-present */

    int64_t idx = bbf_route(r, key, key_size);
    if (idx < 0) return 0; /* sorts before every partition -- definitely absent */

    const bbf_partition_t *e = &r->parts[idx];
    const uint8_t *blob = NULL;
    void *pin = NULL;
    if (r->fetch_fn(r->cb_ctx, e->offset, e->size, &blob, &pin) != 0 || !blob) return -1;

    /* probe the pinned partition in place -- no filter is materialized per query */
    const int c = bloom_filter_contains_serialized(blob, e->size, key, key_size);
    if (pin && r->release_fn) r->release_fn(r->cb_ctx, pin);
    return c;
}

size_t blocked_bloom_reader_resident_bytes(const blocked_bloom_reader_t *r)
{
    return r ? r->resident_bytes : 0;
}

void blocked_bloom_reader_free(blocked_bloom_reader_t *r)
{
    if (!r) return;
    bbf_partitions_free(r->parts, r->num_parts);
    free(r);
}
