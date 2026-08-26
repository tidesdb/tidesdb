/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "base/log.h"
#include "column_family/cf_config.h"
#include "manifest/manifest.h"
#include "manifest/manifest_internal.h"
#include "sstable/btree/btree_internal.h"
#include "sstable/pr_filter.h"
#include "sstable/sstable.h"
#include "txn/wal_record.h"

/* the decoders that read bytes off disk, driven straight from fuzzer input.
 *
 * the model-based harnesses drive the engine through its public api, so every byte they decode was
 * written by the engine itself and is well formed by construction. these decoders are the only
 * place untrusted bytes enter, and a torn write, a truncated tail, or a corrupt field has to be
 * rejected rather than turned into an out-of-bounds read or a wild allocation. that is what this
 * target covers.
 *
 * the first input byte selects a decoder and the rest is its payload, so a single corpus explores
 * all of them. every path either fails or frees what it built, so leaks and overreads surface under
 * the sanitizers rather than passing silently. */

/* how many entries a wal batch is drained for before the target stops, so a crafted count cannot
 * spin the fuzzer instead of failing it */
#define FZD_WAL_MAX_ENTRIES 4096

/* the partition-filter reader fetches blobs through a callback; the fuzz input stands in for the
 * whole file, so a fetch is a bounds-checked slice of it */
typedef struct
{
    const uint8_t *data;
    size_t size;
} fzd_blob_t;

static int fzd_fetch(void *ctx, uint64_t offset, uint32_t size, const uint8_t **out_data,
                     void **out_pin)
{
    const fzd_blob_t *b = ctx;
    if (offset > b->size || (uint64_t)size > b->size - offset) return -1;
    *out_data = b->data + offset;
    *out_pin = NULL;
    return 0;
}

static void fzd_footer(const uint8_t *data, size_t size)
{
    sstable_footer_t footer;
    memset(&footer, 0, sizeof(footer));
    if (sstable_footer_parse(data, size, &footer) != 0) return;

    /* a parsed footer owns its key copies */
    free(footer.min_key);
    free(footer.max_key);
}

static void fzd_cf_config(const uint8_t *data, size_t size)
{
    tidesdb_column_family_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    (void)cf_config_deserialize(data, size, &cfg);
}

static void fzd_wal(const uint8_t *data, size_t size)
{
    tidesdb_wal_cursor_t c;
    memset(&c, 0, sizeof(c));
    if (tidesdb_wal_cursor_init(&c, data, size) != 0) return;

    tidesdb_wal_entry_t e;
    for (int i = 0; i < FZD_WAL_MAX_ENTRIES; i++)
    {
        memset(&e, 0, sizeof(e));
        if (tidesdb_wal_cursor_next(&c, &e) != 1) break;
    }
}

static void fzd_pr_filter(const uint8_t *data, size_t size)
{
    /* the leading bytes carry the directory offset and length the reader would have read from a
     * footer, so the fuzzer controls where in its own buffer the directory is claimed to live */
    if (size < 3) return;
    const uint64_t dir_offset = data[0];
    const uint32_t dir_size = (uint32_t)data[1] | ((uint32_t)data[2] << 8);

    fzd_blob_t blob = {data, size};
    pr_filter_reader_t *r = NULL;
    if (pr_filter_reader_open(&r, dir_offset, dir_size, fzd_fetch, NULL, &blob) != 0) return;

    /* a directory that parsed is then probed, so routing and the per-partition blob read run too */
    const uint8_t key[] = {'k'};
    (void)pr_filter_reader_maybe_contains(r, key, sizeof(key));
    (void)pr_filter_reader_resident_bytes(r);
    pr_filter_reader_free(r);
}

static void fzd_btree_node(const uint8_t *data, size_t size)
{
    arena_t *arena = arena_create(NULL);
    if (!arena) return;

    btree_node_t *node = NULL;
    if (btree_node_deserialize_direct(data, size, &node, arena) == 0 && node)
    {
        /* touch what the decoder reconstructed so a bad length or pointer is read, not just built
         */
        volatile size_t sink = 0;
        for (uint32_t i = 0; i < node->num_entries; i++)
        {
            if (node->keys && node->keys[i] && node->key_sizes) sink += node->key_sizes[i];
            if (node->values && node->values[i]) sink += node->entries[i].value_size;
        }
        (void)sink;
        btree_node_free(node); /* destroys the arena */
        return;
    }
    arena_destroy(arena);
}

/* the manifest is the catalogue, so a batch that decodes wrongly does not corrupt one record -- it
 * decides which sstables the database believes it has. the block manager checksums a batch before
 * this sees it, which means random rot never reaches here, and that is exactly why it is worth
 * driving directly: what is left to get wrong is the record loop itself, walking offsets and
 * lengths that a checksum says nothing about */
static void fzd_manifest(const uint8_t *data, size_t size)
{
    /* the apply path grows the three in-memory arrays and touches nothing else, so a zeroed
     * manifest is a complete one for its purposes -- no log handle, no lock, no file */
    tidesdb_manifest_t m;
    memset(&m, 0, sizeof(m));
    (void)manifest_apply_batch(&m, data, size);

    /* a column family and an sstable each land in a fixed-size slot, but a range tombstone set owns
     * a copy of its blob, so those go back one at a time */
    free(m.cfs);
    free(m.entries);
    for (int i = 0; i < m.num_range_dels; i++) free(m.range_dels[i].blob);
    free(m.range_dels);
}

/* the decoders this target rotates through, selected by the first input byte */
static void (*const fzd_targets[])(const uint8_t *, size_t) = {
    fzd_footer, fzd_cf_config, fzd_wal, fzd_pr_filter, fzd_btree_node, fzd_manifest,
};

#define FZD_TARGET_COUNT (sizeof(fzd_targets) / sizeof(fzd_targets[0]))

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* rejecting a malformed buffer is the expected outcome here, and each rejection logs at ERROR.
     * that is right for a running database and pure noise for this target, where it would bury the
     * result and cost more time than the decode. silence the sink once, on the first input */
    static int logs_silenced = 0;
    if (!logs_silenced)
    {
        atomic_store(&_tidesdb_log_level, TDB_LOG_NONE);
        logs_silenced = 1;
    }

    if (size < 1) return 0;
    fzd_targets[data[0] % FZD_TARGET_COUNT](data + 1, size - 1);
    return 0;
}

#ifdef FUZZ_STANDALONE
/* built without libFuzzer so the target still runs under any compiler: replay given files, or with
 * none generate deterministic pseudo-random inputs so it doubles as a regression test */
#include <stdio.h>

#define FZD_STANDALONE_DEFAULT_ITERS 2000
#define FZD_STANDALONE_MAX_INPUT     1024

static uint64_t fzd_rng_next(uint64_t *state)
{
    uint64_t x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

static long fzd_env_long(const char *name, long fallback)
{
    const char *v = getenv(name);
    return v ? strtol(v, NULL, 10) : fallback;
}

static int fzd_replay_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f)
    {
        fprintf(stderr, "cannot open %s\n", path);
        return 1;
    }
    uint8_t buf[1 << 16];
    const size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    (void)LLVMFuzzerTestOneInput(buf, n);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 1)
    {
        for (int i = 1; i < argc; i++)
            if (fzd_replay_file(argv[i]) != 0) return 1;
        printf("replayed %d input(s)\n", argc - 1);
        return 0;
    }

    const long iters = fzd_env_long("TIDESDB_FUZZ_ITERS", FZD_STANDALONE_DEFAULT_ITERS);
    uint64_t state = (uint64_t)fzd_env_long("TIDESDB_FUZZ_SEED", 0x9E3779B97F4A7C15ULL);
    if (state == 0) state = 0x9E3779B97F4A7C15ULL;

    uint8_t buf[FZD_STANDALONE_MAX_INPUT];
    for (long it = 0; it < iters; it++)
    {
        const size_t n = (size_t)(fzd_rng_next(&state) % FZD_STANDALONE_MAX_INPUT) + 1;
        for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)fzd_rng_next(&state);
        (void)LLVMFuzzerTestOneInput(buf, n);
    }
    printf("decode fuzz ok -- %ld iterations\n", iters);
    return 0;
}
#endif
