/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include "../src/base/errors.h"
#include "../src/io/block_manager.h"
#include "../src/sstable/vlog.h"
#include "../src/sstable/vlog_internal.h" /* the segment table, for the retire guard test */
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define VDIR      "." PATH_SEPARATOR "test_vlog_db"
#define VDIR_MODE 0755

/* a target small enough that a handful of values seals a segment, so tests exercise rolling and
 * reclaim without writing the hundreds of megabytes the shipped default would need */
#define V_SEG_TARGET 4096

/* value sizes either side of the block manager's read-hint boundary */
#define V_SMALL  100
#define V_MEDIUM 1024
#define V_LARGE  40000

/* enough values to fill several segments at the test target */
#define V_MANY 200

/* concurrency shape: readers and writers running against a live reclaim */
#define V_CONC_READERS 4
#define V_CONC_WRITERS 2
#define V_CONC_SEED    64
#define V_CONC_ROUNDS  200

/* how many values each writer adds. the segment table is a fixed 4096 slots, so at this test's
 * deliberately tiny segment target the whole store addresses only about sixteen megabytes --
 * unbounded writers exhaust it in seconds and every append then fails, correctly, because the store
 * cannot name another segment. the budget keeps the run inside that ceiling while still rolling and
 * retiring segments constantly, which is what the test is for */
#define V_CONC_WRITES 1500

/* the segment size and reclaim pacing the concurrency test runs at. a reclaim copies a segment's
 * live values forward as it drains it, so a very small target makes relocation create segments
 * about as fast as it retires them, and a reclaimer spinning with no pause between passes rolls and
 * retires continuously -- together they can exhaust the fixed segment table, at which point a write
 * correctly fails because the store cannot name another segment. neither shape is one a deployment
 * produces: the engine triggers a reclaim only once garbage passes half the store */
#define V_CONC_SEG_TARGET       (256 * 1024)
#define V_CONC_RECLAIM_PAUSE_US 2000

/* per-thread id uniqueness check */
#define V_UNIQ_THREADS 8
#define V_UNIQ_PER     200

/* deterministic byte pattern so a value can be regenerated to compare without keeping it */
static uint8_t *pattern(size_t n, unsigned seed)
{
    uint8_t *b = malloc(n ? n : 1);
    uint32_t s = seed * 2654435761u + 1;
    for (size_t i = 0; i < n; i++)
    {
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;
        b[i] = (uint8_t)(s >> 24);
    }
    return b;
}

/* compressible pattern -- long runs so a codec actually shrinks it */
static uint8_t *runs(size_t n, unsigned seed)
{
    uint8_t *b = malloc(n ? n : 1);
    for (size_t i = 0; i < n; i++) b[i] = (uint8_t)(seed + (i / 64));
    return b;
}

static void fresh_dir(void)
{
    (void)remove_directory(VDIR);
    (void)mkdir(VDIR, VDIR_MODE);
}

/* the pipeline a subsequent put() records with its value, and the registry its ids resolve against.
 * the store carries no codec of its own -- each value records the chain it was written through */
static tidesdb_encoding_registry_t g_vlog_reg;
static uint8_t g_put_ids[TDB_ENCODING_PIPELINE_MAX];
static int g_put_id_count;

static vlog_t *open_store(tidesdb_compression_algorithm_t comp, uint64_t target)
{
    ASSERT_TRUE(tidesdb_encoding_registry_init(&g_vlog_reg) == TDB_SUCCESS);
    g_put_id_count = comp == TDB_COMPRESS_NONE ? 0 : 1;
    g_put_ids[0] = (uint8_t)comp;
    const vlog_config_t cfg = {.encodings = &g_vlog_reg,
                               .sync_mode = BLOCK_MANAGER_SYNC_NONE,
                               .segment_target_bytes = target};
    vlog_t *v = NULL;
    ASSERT_TRUE(vlog_open(VDIR, &cfg, &v) == VLOG_OK);
    ASSERT_TRUE(v != NULL);
    return v;
}

static void assert_reads(vlog_t *v, vlog_id_t id, const uint8_t *want, size_t wlen)
{
    uint8_t *got = NULL;
    size_t glen = 0;
    ASSERT_TRUE(vlog_read(v, id, &got, &glen) == VLOG_OK);
    ASSERT_EQ(glen, wlen);
    ASSERT_EQ(memcmp(got, want, wlen), 0);
    free(got);
}

static void assert_gone(vlog_t *v, vlog_id_t id)
{
    uint8_t *got = NULL;
    size_t glen = 0;
    ASSERT_TRUE(vlog_read(v, id, &got, &glen) == VLOG_ERR_NOT_FOUND);
}

static vlog_id_t put(vlog_t *v, const uint8_t *data, size_t n)
{
    vlog_id_t id = 0;
    ASSERT_TRUE(vlog_write(v, data, n, g_put_ids, g_put_id_count, &id, NULL) == VLOG_OK);
    ASSERT_TRUE(id != VLOG_ID_INVALID);
    return id;
}

static size_t segment_count(vlog_t *v)
{
    vlog_stats_t st;
    ASSERT_TRUE(vlog_get_stats(v, &st) == VLOG_OK);
    return (size_t)st.segment_count;
}

/* state that exactly these ids are still referenced, the way installed sstables do, then reclaim.
 * one pass drops every segment nothing holds, so there is nothing to repeat */
static void reclaim_keeping(vlog_t *v, const uint64_t *keep, size_t n)
{
    vlog_live_reset(v);
    for (size_t i = 0; i < n; i++)
    {
        uint64_t segment = 0, bytes = 0;
        if (vlog_segment_of(v, keep[i], &segment, &bytes) == VLOG_OK)
            vlog_live_add(v, segment, bytes, 1);
    }
    ASSERT_TRUE(vlog_reclaim(v) == VLOG_OK);
}

static void roundtrip_size(size_t n)
{
    fresh_dir();
    vlog_t *v = open_store(TDB_COMPRESS_NONE, 0);
    uint8_t *val = pattern(n, (unsigned)n);
    const vlog_id_t id = put(v, val, n);
    assert_reads(v, id, val, n);
    free(val);
    vlog_close(v);
}

void test_open_fresh_empty(void)
{
    fresh_dir();
    vlog_t *v = open_store(TDB_COMPRESS_NONE, 0);
    vlog_stats_t st;
    ASSERT_TRUE(vlog_get_stats(v, &st) == VLOG_OK);
    ASSERT_EQ((int)st.value_count, 0);
    ASSERT_EQ((int)st.used_bytes, 0);

    /* a fresh store still opens one segment, because appends need somewhere to land */
    ASSERT_EQ((int)st.segment_count, 1);
    ASSERT_EQ((int)vlog_next_id(v), 1);
    vlog_close(v);
}

void test_roundtrip_one_byte(void)
{
    roundtrip_size(1);
}

void test_roundtrip_small(void)
{
    roundtrip_size(V_SMALL);
}

void test_roundtrip_medium(void)
{
    roundtrip_size(V_MEDIUM);
}

void test_roundtrip_large(void)
{
    roundtrip_size(V_LARGE);
}

/* a value packs to about its own size -- one tight block, not a padded slot */
void test_tight_packing(void)
{
    fresh_dir();
    vlog_t *v = open_store(TDB_COMPRESS_NONE, 0);
    uint8_t *val = pattern(V_MEDIUM, 1);
    for (int i = 0; i < V_MANY; i++) (void)put(v, val, V_MEDIUM);

    vlog_stats_t st;
    ASSERT_TRUE(vlog_get_stats(v, &st) == VLOG_OK);
    ASSERT_EQ((int)st.value_count, V_MANY);
    ASSERT_TRUE(st.file_size < (uint64_t)V_MANY * V_MEDIUM * 5 / 4);
    free(val);
    vlog_close(v);
}

void test_stats_used_bytes(void)
{
    fresh_dir();
    vlog_t *v = open_store(TDB_COMPRESS_NONE, 0);
    uint64_t total = 0;
    for (int i = 0; i < 20; i++)
    {
        const size_t n = 300 + (size_t)i * 137;
        uint8_t *val = pattern(n, (unsigned)i);
        (void)put(v, val, n);
        total += n;
        free(val);
    }
    vlog_stats_t st;
    ASSERT_TRUE(vlog_get_stats(v, &st) == VLOG_OK);
    ASSERT_EQ((int)st.value_count, 20);
    ASSERT_TRUE(st.used_bytes == total);
    vlog_close(v);
}

/* one shared store holds values from families with different codecs. the store carries no codec of
 * its own, so a value is decoded by whatever it was written with -- which is the property that lets
 * a db-global value log serve per-family encodings at all */
/* a value is written through a chain of encodings and reads back through exactly that chain, which
 * the block records with it. a store holding values written under different chains decodes each by
 * its own, which is what compaction requires -- it carries a value forward by id without
 * re-encoding it, so the sstable referencing a value can end up recording a different pipeline than
 * the one that wrote it */
void test_stacked_chain_round_trips(void)
{
    fresh_dir();
    vlog_t *v = open_store(TDB_COMPRESS_NONE, 0);

    uint8_t *a = runs(V_LARGE, 5);
    uint8_t *b = runs(V_LARGE, 9);

    const uint8_t two[2] = {TDB_COMPRESS_LZ4, TDB_COMPRESS_ZSTD};
    const uint8_t one[1] = {TDB_COMPRESS_LZ4};
    vlog_id_t stacked = 0, single = 0;
    ASSERT_TRUE(vlog_write(v, a, V_LARGE, two, 2, &stacked, NULL) == VLOG_OK);
    ASSERT_TRUE(vlog_write(v, b, V_LARGE, one, 1, &single, NULL) == VLOG_OK);

    /* each decodes by the chain it was written through, not by the other's */
    assert_reads(v, stacked, a, V_LARGE);
    assert_reads(v, single, b, V_LARGE);

    /* and after a reopen, where the chains come only from the blocks themselves */
    vlog_close(v);
    v = open_store(TDB_COMPRESS_NONE, 0);
    assert_reads(v, stacked, a, V_LARGE);
    assert_reads(v, single, b, V_LARGE);

    free(a);
    free(b);
    vlog_close(v);
}

void test_mixed_codecs_in_one_store(void)
{
    fresh_dir();
    vlog_t *v = open_store(TDB_COMPRESS_NONE, 0);

    uint8_t *a = runs(V_LARGE, 5);
    uint8_t *b = runs(V_LARGE, 7);
    vlog_id_t plain = 0, packed = 0;
    ASSERT_TRUE(vlog_write(v, a, V_LARGE, NULL, 0, &plain, NULL) == VLOG_OK);
    const uint8_t lz4_ids[1] = {TDB_COMPRESS_LZ4};
    ASSERT_TRUE(vlog_write(v, b, V_LARGE, lz4_ids, 1, &packed, NULL) == VLOG_OK);

    /* both read back as themselves, neither decoded with the other's codec */
    assert_reads(v, plain, a, V_LARGE);
    assert_reads(v, packed, b, V_LARGE);

    /* and the compressed one really is smaller on disk than the verbatim one, so the codec was
     * applied rather than merely recorded */
    vlog_stats_t st;
    ASSERT_TRUE(vlog_get_stats(v, &st) == VLOG_OK);
    ASSERT_TRUE(st.file_size < 2 * V_LARGE);

    /* the values survive a reopen, which reads each codec back off the block rather than a config
     */
    vlog_close(v);
    v = open_store(TDB_COMPRESS_NONE, 0);
    assert_reads(v, plain, a, V_LARGE);
    assert_reads(v, packed, b, V_LARGE);

    free(a);
    free(b);
    vlog_close(v);
}

void test_compression_compressible(void)
{
    fresh_dir();
    vlog_t *v = open_store(TDB_COMPRESS_LZ4, 0);
    uint8_t *val = runs(V_LARGE, 5);
    const vlog_id_t id = put(v, val, V_LARGE);

    vlog_stats_t st;
    ASSERT_TRUE(vlog_get_stats(v, &st) == VLOG_OK);
    ASSERT_TRUE(st.file_size < V_LARGE / 2); /* compressible data really shrank on disk */
    ASSERT_TRUE(st.used_bytes == V_LARGE);   /* used_bytes tracks the uncompressed length */
    assert_reads(v, id, val, V_LARGE);
    free(val);
    vlog_close(v);
}

void test_compression_incompressible(void)
{
    fresh_dir();
    vlog_t *v = open_store(TDB_COMPRESS_LZ4, 0);
    uint8_t *val = pattern(V_LARGE, 777);
    const vlog_id_t id = put(v, val, V_LARGE);
    assert_reads(v, id, val, V_LARGE);
    free(val);
    vlog_close(v);
}

void test_writes_roll_into_several_segments(void)
{
    fresh_dir();
    vlog_t *v = open_store(TDB_COMPRESS_NONE, V_SEG_TARGET);
    uint8_t *val = pattern(V_MEDIUM, 5);
    uint64_t ids[V_MANY];
    for (int i = 0; i < V_MANY; i++) ids[i] = put(v, val, V_MEDIUM);

    /* the store spread the values across more than one file, which is what gives a reclaim a
     * sealed segment to work on, and every value is still resolvable across the split */
    ASSERT_TRUE(segment_count(v) > 1);
    for (int i = 0; i < V_MANY; i++) assert_reads(v, ids[i], val, V_MEDIUM);
    free(val);
    vlog_close(v);
}

void test_reclaim_keeps_live_values_readable(void)
{
    fresh_dir();
    vlog_t *v = open_store(TDB_COMPRESS_NONE, V_SEG_TARGET);

    uint64_t ids[V_MANY];
    uint8_t *val = pattern(V_MEDIUM, 9);
    for (int i = 0; i < V_MANY; i++) ids[i] = put(v, val, V_MEDIUM);

    /* keep every other id, so every segment holds a mix of live and dead. a segment holding
     * anything live is not reclaimable however much of it is garbage, since dropping it would take
     * the live values with it */
    uint64_t keep[V_MANY / 2];
    for (int i = 0; i < V_MANY / 2; i++) keep[i] = ids[i * 2];
    const size_t before = segment_count(v);
    reclaim_keeping(v, keep, V_MANY / 2);

    ASSERT_EQ((int)segment_count(v), (int)before);
    for (int i = 0; i < V_MANY / 2; i++) assert_reads(v, keep[i], val, V_MEDIUM);
    free(val);
    vlog_close(v);
}

void test_reclaim_drops_dead_values(void)
{
    fresh_dir();
    vlog_t *v = open_store(TDB_COMPRESS_NONE, V_SEG_TARGET);

    uint64_t ids[V_MANY];
    uint8_t *val = pattern(V_MEDIUM, 13);
    for (int i = 0; i < V_MANY; i++) ids[i] = put(v, val, V_MEDIUM);
    free(val);

    const size_t before = segment_count(v);
    uint64_t keep[1] = {ids[V_MANY - 1]}; /* only the newest survives */
    reclaim_keeping(v, keep, 1);

    /* the drained segment's file is gone, and the values it held no longer resolve */
    ASSERT_TRUE(segment_count(v) < before);
    assert_gone(v, ids[0]);
    vlog_close(v);
}

void test_reclaim_leaves_the_active_segment_alone(void)
{
    fresh_dir();
    vlog_t *v = open_store(TDB_COMPRESS_NONE, 0);

    uint8_t *val = pattern(V_MEDIUM, 17);
    const vlog_id_t id = put(v, val, V_MEDIUM);

    /* with the shipped segment target nothing has sealed, so the only segment is the active one.
     * a reclaim must decline it rather than unlink the file it is appending to */
    ASSERT_TRUE(vlog_reclaim(v) == VLOG_OK);
    assert_reads(v, id, val, V_MEDIUM);
    ASSERT_EQ((int)segment_count(v), 1);
    free(val);
    vlog_close(v);
}

void test_reclaim_spares_what_a_builder_may_have_written(void)
{
    fresh_dir();
    vlog_t *v = open_store(TDB_COMPRESS_NONE, V_SEG_TARGET);

    /* a builder in flight has written values no installed table names yet, so an empty live set
     * would otherwise drop every segment it just filled. this is the window a flush spanning a
     * segment roll sits in, and losing it loses the values the flush is about to reference */
    const int build_token = vlog_build_enter(v);

    uint64_t ids[V_MANY];
    uint8_t *val = pattern(V_MEDIUM, 19);
    for (int i = 0; i < V_MANY; i++) ids[i] = put(v, val, V_MEDIUM);

    reclaim_keeping(v, NULL, 0);
    for (int i = 0; i < V_MANY; i++) assert_reads(v, ids[i], val, V_MEDIUM);

    /* once the builder is done and still nothing references them, they go */
    vlog_build_leave(v, build_token);
    reclaim_keeping(v, NULL, 0);
    assert_gone(v, ids[0]);
    free(val);
    vlog_close(v);
}

/* the floor a builder holds must describe that builder alone. under a steady write load flushes and
 * compactions overlap without a gap, so a floor that could only be cleared when the last builder
 * left would stay pinned wherever the first one found it and nothing above it could ever be
 * reclaimed -- which is reclamation stopping entirely on exactly the workload that needs it */
void test_reclaim_floor_follows_the_builders_still_running(void)
{
    fresh_dir();
    vlog_t *v = open_store(TDB_COMPRESS_NONE, V_SEG_TARGET);

    /* the first builder starts at the oldest segment and writes enough to seal several */
    const int first = vlog_build_enter(v);
    uint64_t ids[V_MANY];
    uint8_t *val = pattern(V_MEDIUM, 37);
    for (int i = 0; i < V_MANY; i++) ids[i] = put(v, val, V_MEDIUM);

    /* a second builder overlaps it, starting at a much later segment */
    const int second = vlog_build_enter(v);

    /* the first finishes; the second is still running, so only what it might touch is protected */
    vlog_build_leave(v, first);

    const size_t before = segment_count(v);
    reclaim_keeping(v, NULL, 0);

    /* the early segments the departed builder held are gone, without waiting for the second */
    ASSERT_TRUE(segment_count(v) < before);
    assert_gone(v, ids[0]);

    vlog_build_leave(v, second);
    free(val);
    vlog_close(v);
}

/* a sealed segment's descriptor can be taken back while the segment stays usable, so a store
 * holding thousands of them cannot exhaust the process. the value it holds must still read, since
 * an eviction that lost data would be indistinguishable from a reclaim that dropped a live
 * segment */
void test_idle_segments_give_back_their_descriptors(void)
{
    fresh_dir();
    vlog_t *v = open_store(TDB_COMPRESS_NONE, V_SEG_TARGET);

    uint64_t ids[V_MANY];
    uint8_t *val = pattern(V_MEDIUM, 43);
    for (int i = 0; i < V_MANY; i++) ids[i] = put(v, val, V_MEDIUM);

    /* every sealed segment is idle, so all but the one taking appends give theirs back */
    const int freed = vlog_evict_idle_segments(v, 0);
    ASSERT_TRUE(freed >= 1);

    /* reading reopens the file underneath, so the values are all still there */
    for (int i = 0; i < V_MANY; i++) assert_reads(v, ids[i], val, V_MEDIUM);

    /* and with the files reopened by those reads, there is something to give back again */
    ASSERT_TRUE(vlog_evict_idle_segments(v, 0) >= 1);

    /* a bound is honoured rather than ignored */
    for (int i = 0; i < V_MANY; i++) assert_reads(v, ids[i], val, V_MEDIUM);
    ASSERT_EQ(vlog_evict_idle_segments(v, 1), 1);

    /* writing still works with segments evicted underneath */
    const vlog_id_t fresh = put(v, val, V_MEDIUM);
    assert_reads(v, fresh, val, V_MEDIUM);

    free(val);
    vlog_close(v);
}

/* a value larger than the segment target is not split -- one value is one block, always. it lands
 * whole in a fresh segment that simply overshoots, which is the case where the target stops being a
 * size and becomes only a roll threshold */
void test_a_value_larger_than_a_segment_is_not_split(void)
{
    fresh_dir();
    vlog_t *v = open_store(TDB_COMPRESS_NONE, V_SEG_TARGET);

    /* an order of magnitude past the target, so no segment could hold it within its bound */
    const size_t huge = V_SEG_TARGET * 10;
    uint8_t *big = pattern(huge, 47);
    const vlog_id_t id = put(v, big, huge);

    /* it reads back as one value rather than being reassembled from pieces */
    assert_reads(v, id, big, huge);

    /* and the store keeps working around it: the next write rolls off the oversized segment */
    uint8_t *small = pattern(V_SMALL, 48);
    const vlog_id_t after = put(v, small, V_SMALL);
    assert_reads(v, after, small, V_SMALL);
    assert_reads(v, id, big, huge);

    /* the segment it occupies is reclaimable as a whole once nothing references it, which is what
     * makes an oversized value the easiest case rather than the hardest */
    uint64_t keep[1] = {after};
    reclaim_keeping(v, keep, 1);
    assert_gone(v, id);
    assert_reads(v, after, small, V_SMALL);

    /* it survives a reopen, so the oversized block is framed on disk the same as any other */
    uint8_t *again = pattern(huge, 49);
    const vlog_id_t second = put(v, again, huge);
    vlog_close(v);
    v = open_store(TDB_COMPRESS_NONE, V_SEG_TARGET);
    assert_reads(v, second, again, huge);

    free(again);
    free(small);
    free(big);
    vlog_close(v);
}

/* a family can change its codec, and compaction rewrites values under whichever pipeline is
 * merging them, so one ratio for the whole store would average across chains and describe none of
 * them. what each chain achieved is attributed to the values that chain actually wrote */
void test_chain_stats_follow_the_values_not_the_configuration(void)
{
    fresh_dir();
    vlog_t *v = open_store(TDB_COMPRESS_NONE, V_SEG_TARGET);

    /* compressible, so a codec visibly shrinks what it writes */
    uint8_t body[4096];
    memset(body, 'Q', sizeof(body));

    const uint8_t none[1] = {0};
    const uint8_t zstd[1] = {(uint8_t)TDB_COMPRESS_ZSTD};

    /* the first values go in verbatim, then the store is written through a codec, as a family
     * changing its configuration part way through its life would leave behind */
    uint64_t plain[4], coded[4];
    for (int i = 0; i < 4; i++)
        ASSERT_TRUE(vlog_write(v, body, sizeof(body), none, 0, &plain[i], NULL) == VLOG_OK);
    for (int i = 0; i < 4; i++)
        ASSERT_TRUE(vlog_write(v, body, sizeof(body), zstd, 1, &coded[i], NULL) == VLOG_OK);

    vlog_chain_stats_t chains[VLOG_MAX_CHAINS];
    size_t n = 0;
    ASSERT_TRUE(vlog_get_chain_stats(v, chains, VLOG_MAX_CHAINS, &n) == VLOG_OK);
    ASSERT_EQ((int)n, 2); /* the two chains are kept apart rather than summed */

    for (size_t i = 0; i < n; i++)
    {
        ASSERT_EQ((int)chains[i].value_count, 4);
        ASSERT_TRUE(chains[i].used_bytes == 4 * sizeof(body));

        if (chains[i].id_count == 0)
        {
            /* stored verbatim, so the framing is all that stands between logical and physical */
            ASSERT_TRUE(chains[i].stored_bytes >= chains[i].used_bytes);
        }
        else
        {
            /* and the coded chain shows what the codec actually bought on its own values */
            ASSERT_EQ(chains[i].ids[0], (uint8_t)TDB_COMPRESS_ZSTD);
            ASSERT_TRUE(chains[i].stored_bytes < chains[i].used_bytes / 2);
        }
    }

    /* the attribution survives a reopen, since it is read back off the values themselves rather
     * than from any configuration the store was carrying */
    vlog_close(v);
    v = open_store(TDB_COMPRESS_NONE, V_SEG_TARGET);
    ASSERT_TRUE(vlog_get_chain_stats(v, chains, VLOG_MAX_CHAINS, &n) == VLOG_OK);
    ASSERT_EQ((int)n, 2);
    vlog_close(v);
}

void test_reclaim_is_idempotent(void)
{
    fresh_dir();
    vlog_t *v = open_store(TDB_COMPRESS_NONE, V_SEG_TARGET);

    uint64_t ids[V_MANY];
    uint8_t *val = pattern(V_MEDIUM, 23);
    for (int i = 0; i < V_MANY; i++) ids[i] = put(v, val, V_MEDIUM);

    uint64_t keep[V_MANY];
    for (int i = 0; i < V_MANY; i++) keep[i] = ids[i];
    reclaim_keeping(v, keep, V_MANY);
    const size_t settled = segment_count(v);
    reclaim_keeping(v, keep, V_MANY);

    /* nothing is dead, so a further pass neither frees a segment nor loses a value */
    ASSERT_EQ((int)segment_count(v), (int)settled);
    for (int i = 0; i < V_MANY; i++) assert_reads(v, ids[i], val, V_MEDIUM);
    free(val);
    vlog_close(v);
}

void test_write_after_reclaim(void)
{
    fresh_dir();
    vlog_t *v = open_store(TDB_COMPRESS_NONE, V_SEG_TARGET);

    uint64_t ids[V_MANY];
    uint8_t *val = pattern(V_MEDIUM, 29);
    for (int i = 0; i < V_MANY; i++) ids[i] = put(v, val, V_MEDIUM);

    uint64_t keep[1] = {ids[V_MANY - 1]};
    reclaim_keeping(v, keep, 1);

    /* the store still takes appends after a segment was unlinked under it */
    uint8_t *fresh = pattern(V_MEDIUM, 31);
    const vlog_id_t id = put(v, fresh, V_MEDIUM);
    assert_reads(v, id, fresh, V_MEDIUM);
    ASSERT_TRUE(id > ids[V_MANY - 1]);
    free(fresh);
    free(val);
    vlog_close(v);
}

void test_recover_keeps_everything(void)
{
    fresh_dir();
    vlog_t *v = open_store(TDB_COMPRESS_NONE, V_SEG_TARGET);

    uint64_t ids[V_MANY];
    uint8_t *val = pattern(V_MEDIUM, 37);
    for (int i = 0; i < V_MANY; i++) ids[i] = put(v, val, V_MEDIUM);
    vlog_close(v);

    v = open_store(TDB_COMPRESS_NONE, V_SEG_TARGET);
    for (int i = 0; i < V_MANY; i++) assert_reads(v, ids[i], val, V_MEDIUM);

    /* ids resume above every recovered value, so a reopened store never reissues one */
    ASSERT_TRUE(vlog_next_id(v) > ids[V_MANY - 1]);
    free(val);
    vlog_close(v);
}

void test_recover_after_reclaim(void)
{
    fresh_dir();
    vlog_t *v = open_store(TDB_COMPRESS_NONE, V_SEG_TARGET);

    uint64_t ids[V_MANY];
    uint8_t *val = pattern(V_MEDIUM, 41);
    for (int i = 0; i < V_MANY; i++) ids[i] = put(v, val, V_MEDIUM);

    uint64_t keep[1] = {ids[V_MANY - 1]};
    reclaim_keeping(v, keep, 1);
    vlog_close(v);

    /* the drop is a file unlink, so a reopen rebuilds its index from what is left rather than
     * resurrecting the values whose segments went */
    v = open_store(TDB_COMPRESS_NONE, V_SEG_TARGET);
    assert_reads(v, keep[0], val, V_MEDIUM);
    assert_gone(v, ids[0]);
    free(val);
    vlog_close(v);
}

void test_recover_appends_to_a_fresh_segment(void)
{
    fresh_dir();
    vlog_t *v = open_store(TDB_COMPRESS_NONE, 0);
    uint8_t *val = pattern(V_MEDIUM, 43);
    (void)put(v, val, V_MEDIUM);
    const size_t before = segment_count(v);
    vlog_close(v);

    /* reopening leaves what was there alone and appends into a new segment, so a segment sealed
     * before a restart stays immutable across it */
    v = open_store(TDB_COMPRESS_NONE, 0);
    ASSERT_EQ((int)segment_count(v), (int)before + 1);
    const vlog_id_t id = put(v, val, V_MEDIUM);
    assert_reads(v, id, val, V_MEDIUM);
    free(val);
    vlog_close(v);
}

void test_recover_torn_tail_ignored(void)
{
    fresh_dir();
    vlog_t *v = open_store(TDB_COMPRESS_NONE, 0);
    uint8_t *a = pattern(V_SMALL, 1), *b = pattern(V_MEDIUM, 2);
    const vlog_id_t ia = put(v, a, V_SMALL);
    const vlog_id_t ib = put(v, b, V_MEDIUM);

    vlog_segment_info_t infos[VLOG_MAX_SEGMENTS];
    size_t n = 0;
    ASSERT_TRUE(vlog_list_segments(v, infos, VLOG_MAX_SEGMENTS, &n) == VLOG_OK);
    ASSERT_EQ((int)n, 1);
    char path[512];
    snprintf(path, sizeof(path), "%s%s%s", VDIR, PATH_SEPARATOR, infos[0].name);
    vlog_close(v);

    /* cut the file short mid-way through the second value's block, the shape a crash during an
     * append leaves behind */
    FILE *f = fopen(path, "rb");
    ASSERT_TRUE(f != NULL);
    ASSERT_EQ(fseek(f, 0, SEEK_END), 0);
    const long full = ftell(f);
    ASSERT_TRUE(full > (long)V_MEDIUM);
    const size_t kept = (size_t)full - V_MEDIUM / 2;
    uint8_t *head = malloc(kept);
    ASSERT_TRUE(head != NULL);
    ASSERT_EQ(fseek(f, 0, SEEK_SET), 0);
    ASSERT_EQ(fread(head, 1, kept, f), kept);
    fclose(f);

    /* rewritten short rather than truncated in place, so the test needs nothing beyond stdio */
    f = fopen(path, "wb");
    ASSERT_TRUE(f != NULL);
    ASSERT_EQ(fwrite(head, 1, kept, f), kept);
    fclose(f);
    free(head);

    /* recovery adopts what is intact and stops at the tear, so the value written before it reads
     * back and the torn one is simply absent rather than corrupt */
    v = open_store(TDB_COMPRESS_NONE, 0);
    assert_reads(v, ia, a, V_SMALL);
    assert_gone(v, ib);
    free(a);
    free(b);
    vlog_close(v);
}

void test_read_detects_corruption(void)
{
    fresh_dir();
    vlog_t *v = open_store(TDB_COMPRESS_NONE, 0);
    uint8_t *a = pattern(V_MEDIUM, 4);
    const vlog_id_t ia = put(v, a, V_MEDIUM);
    assert_reads(v, ia, a, V_MEDIUM);

    vlog_segment_info_t infos[VLOG_MAX_SEGMENTS];
    size_t n = 0;
    ASSERT_TRUE(vlog_list_segments(v, infos, VLOG_MAX_SEGMENTS, &n) == VLOG_OK);
    char path[512];
    snprintf(path, sizeof(path), "%s%s%s", VDIR, PATH_SEPARATOR, infos[0].name);
    vlog_close(v);

    /* flip a byte inside the block's payload, which the block checksum catches. it is caught at
     * open rather than at read -- the reopen below rebuilds the id index by scanning blocks, and a
     * block that fails its checksum is skipped, so the id never enters the index at all */
    FILE *f = fopen(path, "r+b");
    ASSERT_TRUE(f != NULL);
    ASSERT_EQ(fseek(f, (long)(BLOCK_MANAGER_HEADER_SIZE + BLOCK_MANAGER_BLOCK_HEADER_SIZE + 40),
                    SEEK_SET),
              0);
    const uint8_t bad = 0xFF;
    fwrite(&bad, 1, 1, f);
    fclose(f);

    v = open_store(TDB_COMPRESS_NONE, 0);
    uint8_t *got = NULL;
    size_t gl = 0;
    /* so the value reads as absent rather than as damaged, and never as wrong bytes. absence is
     * what the layer above turns into a failure -- a point read retries it and then reports io, an
     * iterator reports io outright -- because an sstable still holding the reference means the
     * value cannot legitimately be missing */
    ASSERT_EQ(vlog_read(v, ia, &got, &gl), VLOG_ERR_NOT_FOUND);
    ASSERT_TRUE(got == NULL);
    free(a);
    vlog_close(v);
}

/* a handle opened with no encoding registry, standing in for a build lacking the codecs a value was
 * written through, or for a caller that never configured any */
static vlog_t *open_store_without_encodings(void)
{
    const vlog_config_t cfg = {
        .encodings = NULL, .sync_mode = BLOCK_MANAGER_SYNC_NONE, .segment_target_bytes = 0};
    vlog_t *v = NULL;
    ASSERT_TRUE(vlog_open(VDIR, &cfg, &v) == VLOG_OK);
    ASSERT_TRUE(v != NULL);
    return v;
}

/* a value whose chain the reader cannot resolve is unreadable, and unreadable has to be reported
 * rather than answered with the stored bytes. the stored form of a compressed value is a valid
 * block holding bytes that are not the value, so this is the one corruption shape a checksum cannot
 * catch -- handing them back would be a silent wrong read rather than a detected failure */
void test_read_reports_corruption_when_the_chain_cannot_be_resolved(void)
{
    fresh_dir();
    vlog_t *v = open_store(TDB_COMPRESS_NONE, 0);
    uint8_t *packed = runs(V_LARGE, 11);
    const uint8_t lz4_ids[1] = {TDB_COMPRESS_LZ4};
    vlog_id_t id = 0;
    ASSERT_TRUE(vlog_write(v, packed, V_LARGE, lz4_ids, 1, &id, NULL) == VLOG_OK);
    assert_reads(v, id, packed, V_LARGE);
    vlog_close(v);

    /* the same segments, read by a handle that cannot resolve the chain the value carries */
    v = open_store_without_encodings();
    uint8_t *got = NULL;
    size_t glen = 0;
    ASSERT_EQ(vlog_read(v, id, &got, &glen), VLOG_ERR_CORRUPTION);
    ASSERT_TRUE(got == NULL);
    vlog_close(v);

    /* and reads as itself again once the registry is back, so the failure was the reader's missing
     * codec and not anything the store did to the value */
    v = open_store(TDB_COMPRESS_NONE, 0);
    assert_reads(v, id, packed, V_LARGE);
    vlog_close(v);
    free(packed);
}

void test_stats_report_reclaim_activity(void)
{
    fresh_dir();
    vlog_t *v = open_store(TDB_COMPRESS_NONE, V_SEG_TARGET);

    uint64_t ids[V_MANY];
    uint8_t *val = pattern(V_MEDIUM, 67);
    for (int i = 0; i < V_MANY; i++) ids[i] = put(v, val, V_MEDIUM);
    free(val);

    vlog_stats_t before;
    ASSERT_TRUE(vlog_get_stats(v, &before) == VLOG_OK);
    ASSERT_EQ((int)before.reclaim_passes, 0);
    ASSERT_EQ((int)before.segments_retired, 0);
    ASSERT_EQ((int)before.live_bytes, 0); /* nothing has reported holding anything yet */

    /* dead space is visible before any reclaim runs, which is what lets an operator see work
     * pending rather than only work done */
    ASSERT_TRUE(before.dead_bytes > 0);

    uint64_t keep[1] = {ids[V_MANY - 1]};
    reclaim_keeping(v, keep, 1);

    vlog_stats_t after;
    ASSERT_TRUE(vlog_get_stats(v, &after) == VLOG_OK);

    /* one call, and it dropped every segment nothing referenced rather than stopping at the first
     */
    ASSERT_EQ((int)after.reclaim_passes, 1);
    ASSERT_TRUE(after.segments_retired >= 1);

    /* the one value still referenced is what the store now reports as live, and the space it
     * reclaimed shows as a file smaller than it was */
    ASSERT_TRUE(after.live_bytes > 0);
    ASSERT_TRUE(after.file_size < before.file_size);
    vlog_close(v);
}

void test_stats_counters_are_per_handle(void)
{
    fresh_dir();
    vlog_t *v = open_store(TDB_COMPRESS_NONE, V_SEG_TARGET);
    uint64_t ids[V_MANY];
    uint8_t *val = pattern(V_MEDIUM, 71);
    for (int i = 0; i < V_MANY; i++) ids[i] = put(v, val, V_MEDIUM);
    free(val);

    uint64_t keep[1] = {ids[V_MANY - 1]};
    reclaim_keeping(v, keep, 1);
    vlog_close(v);

    /* the activity counters describe what this handle did, so a reopen starts them at zero while
     * the space figures continue to describe the store on disk */
    v = open_store(TDB_COMPRESS_NONE, V_SEG_TARGET);
    vlog_stats_t st;
    ASSERT_TRUE(vlog_get_stats(v, &st) == VLOG_OK);
    ASSERT_EQ((int)st.reclaim_passes, 0);
    ASSERT_EQ((int)st.segments_retired, 0);
    ASSERT_TRUE(st.value_count > 0);
    vlog_close(v);
}

void test_reclaim_of_an_all_dead_segment_moves_nothing(void)
{
    fresh_dir();
    vlog_t *v = open_store(TDB_COMPRESS_NONE, V_SEG_TARGET);

    uint64_t ids[V_MANY];
    uint8_t *val = pattern(V_MEDIUM, 73);
    for (int i = 0; i < V_MANY; i++) ids[i] = put(v, val, V_MEDIUM);
    free(val);

    /* keep only the newest, so the oldest segments are entirely dead and dropping one is pure
     * reclamation -- the file is unlinked and nothing is read or copied to do it */
    uint64_t keep[1] = {ids[V_MANY - 1]};
    reclaim_keeping(v, keep, 1);

    vlog_stats_t st;
    ASSERT_TRUE(vlog_get_stats(v, &st) == VLOG_OK);
    ASSERT_TRUE(st.segments_retired >= 1);
    ASSERT_TRUE(st.live_bytes > 0); /* the one kept value still counts */
    vlog_close(v);
}

void test_retire_refuses_the_segment_taking_appends(void)
{
    fresh_dir();
    vlog_t *v = open_store(TDB_COMPRESS_NONE, V_SEG_TARGET);

    /* enough to roll at least once, so the active slot is one the reclaim loop walks over rather
     * than the very first it looks at */
    uint8_t *val = pattern(V_MEDIUM, 91);
    for (int i = 0; i < V_MANY; i++) (void)put(v, val, V_MEDIUM);
    ASSERT_TRUE(segment_count(v) > 1);

    /* a reclaim pass decides a slot is reclaimable and only then retires it, so a roll landing
     * between the two hands retire the segment now taking appends. retiring it would unlink the
     * open file and leave every later append spinning on a slot that never reopens, reported as a
     * store with no room left rather than as the bug it is. the guard is the last word, so calling
     * retire on the active slot directly is the same question the race asks */
    const uint32_t active = atomic_load(&v->active_slot);
    ASSERT_EQ(vlog_segment_retire(v, active), VLOG_ERR_BUSY);

    /* the refusal has to leave the segment usable, not merely undeleted -- the guard restores the
     * refcount it took to ask, and a botched restore strands the slot just as thoroughly */
    ASSERT_EQ((int)atomic_load(&v->active_slot), (int)active);
    uint64_t id = 0;
    ASSERT_EQ(vlog_write(v, val, V_MEDIUM, NULL, 0, &id, NULL), VLOG_OK);

    uint8_t *got = NULL;
    size_t got_size = 0;
    ASSERT_EQ(vlog_read(v, id, &got, &got_size), VLOG_OK);
    ASSERT_EQ((int)got_size, V_MEDIUM);
    ASSERT_EQ(memcmp(got, val, V_MEDIUM), 0);
    free(got);
    free(val);
    vlog_close(v);
}

void test_list_segments_reports_each(void)
{
    fresh_dir();
    vlog_t *v = open_store(TDB_COMPRESS_NONE, V_SEG_TARGET);
    uint8_t *val = pattern(V_MEDIUM, 47);
    for (int i = 0; i < V_MANY; i++) (void)put(v, val, V_MEDIUM);
    free(val);

    vlog_segment_info_t infos[VLOG_MAX_SEGMENTS];
    size_t n = 0;
    ASSERT_TRUE(vlog_list_segments(v, infos, VLOG_MAX_SEGMENTS, &n) == VLOG_OK);
    ASSERT_EQ((int)n, (int)segment_count(v));
    for (size_t i = 0; i < n; i++)
    {
        ASSERT_TRUE(infos[i].logical_size > 0);
        const size_t nlen = strlen(infos[i].name);
        const size_t elen = strlen(VLOG_SEGMENT_EXT);
        ASSERT_TRUE(nlen > elen);
        ASSERT_EQ(strcmp(infos[i].name + (nlen - elen), VLOG_SEGMENT_EXT), 0);
    }

    /* a caller that cannot hold every segment is told so rather than handed a truncated set it
     * would copy as though it were complete */
    ASSERT_TRUE(vlog_list_segments(v, infos, 1, &n) == VLOG_ERR_FULL);
    vlog_close(v);
}

void test_sync_succeeds(void)
{
    fresh_dir();
    vlog_t *v = open_store(TDB_COMPRESS_NONE, V_SEG_TARGET);
    uint8_t *val = pattern(V_MEDIUM, 53);
    for (int i = 0; i < V_MANY; i++) (void)put(v, val, V_MEDIUM);
    free(val);
    ASSERT_TRUE(vlog_sync(v) == VLOG_OK);
    vlog_close(v);
}

void test_invalid_args(void)
{
    fresh_dir();
    vlog_t *v = open_store(TDB_COMPRESS_NONE, 0);
    vlog_id_t id = 0;
    uint8_t *out = NULL;
    size_t olen = 0;
    const uint8_t byte = 'x';
    vlog_t *tmp = NULL;
    const vlog_config_t cfg = {.sync_mode = BLOCK_MANAGER_SYNC_NONE, .segment_target_bytes = 0};

    ASSERT_TRUE(vlog_open(NULL, &cfg, &tmp) == VLOG_ERR_INVALID);
    ASSERT_TRUE(vlog_open(VDIR, NULL, &tmp) == VLOG_ERR_INVALID);
    ASSERT_TRUE(vlog_open(VDIR, &cfg, NULL) == VLOG_ERR_INVALID);
    ASSERT_TRUE(vlog_write(NULL, &byte, 1, NULL, 0, &id, NULL) == VLOG_ERR_INVALID);
    ASSERT_TRUE(vlog_write(v, NULL, 1, NULL, 0, &id, NULL) == VLOG_ERR_INVALID);
    ASSERT_TRUE(vlog_write(v, &byte, 0, NULL, 0, &id, NULL) == VLOG_ERR_INVALID);
    ASSERT_TRUE(vlog_write(v, &byte, 1, NULL, 0, NULL, NULL) == VLOG_ERR_INVALID);
    ASSERT_TRUE(vlog_read(v, VLOG_ID_INVALID, &out, &olen) == VLOG_ERR_INVALID);
    ASSERT_TRUE(vlog_read(NULL, 1, &out, &olen) == VLOG_ERR_INVALID);
    ASSERT_TRUE(vlog_read(v, 12345, &out, &olen) == VLOG_ERR_NOT_FOUND);
    ASSERT_TRUE(vlog_reclaim(NULL) == VLOG_ERR_INVALID);
    ASSERT_EQ(vlog_mark_drainable(NULL), 0);
    ASSERT_EQ(vlog_should_respill(NULL, 1), 0);
    vlog_build_leave(NULL, 0); /* a null handle unwinds rather than crashing */
    ASSERT_EQ(vlog_should_respill(v, VLOG_ID_INVALID), 0);
    ASSERT_TRUE(vlog_sync(NULL) == VLOG_ERR_INVALID);
    ASSERT_TRUE(vlog_get_stats(v, NULL) == VLOG_ERR_INVALID);
    ASSERT_TRUE(vlog_list_segments(v, NULL, 0, NULL) == VLOG_ERR_INVALID);
    ASSERT_EQ((int)vlog_next_id(NULL), 0);

    /* closing a null handle is a no-op rather than a crash, so an error path can unwind blindly */
    vlog_close(NULL);
    vlog_close(v);
}

void test_many_values_stress(void)
{
    fresh_dir();
    vlog_t *v = open_store(TDB_COMPRESS_LZ4, V_SEG_TARGET);

    uint64_t ids[V_MANY];
    for (int i = 0; i < V_MANY; i++)
    {
        const size_t n = 100 + (size_t)((i * 131) % 20000);
        uint8_t *val = (i & 1) ? pattern(n, (unsigned)i) : runs(n, (unsigned)i);
        ids[i] = put(v, val, n);
        assert_reads(v, ids[i], val, n);
        free(val);
    }

    uint64_t keep[V_MANY];
    size_t nk = 0;
    for (int i = 0; i < V_MANY; i++)
        if (i % 3 == 0) keep[nk++] = ids[i];
    reclaim_keeping(v, keep, nk);

    for (int i = 0; i < V_MANY; i++)
    {
        if (i % 3 != 0) continue;
        const size_t n = 100 + (size_t)((i * 131) % 20000);
        uint8_t *val = (i & 1) ? pattern(n, (unsigned)i) : runs(n, (unsigned)i);
        assert_reads(v, ids[i], val, n);
        free(val);
    }
    vlog_close(v);
}

static vlog_t *g_uniq_v;
static vlog_id_t g_uniq_ids[V_UNIQ_THREADS][V_UNIQ_PER];

/* every writer gets its own ids, whatever the interleaving; a reused id would alias two values */
static void *uniq_worker(void *arg)
{
    const long t = (long)arg;
    uint8_t *b = pattern(V_SMALL, (unsigned)t);
    for (int i = 0; i < V_UNIQ_PER; i++)
    {
        vlog_id_t id = 0;
        ASSERT_TRUE(vlog_write(g_uniq_v, b, V_SMALL, NULL, 0, &id, NULL) == VLOG_OK);
        g_uniq_ids[t][i] = id;
    }
    free(b);
    return NULL;
}

void test_concurrent_ids_are_unique(void)
{
    fresh_dir();
    g_uniq_v = open_store(TDB_COMPRESS_NONE, V_SEG_TARGET);

    pthread_t th[V_UNIQ_THREADS];
    for (long t = 0; t < V_UNIQ_THREADS; t++)
        ASSERT_EQ(pthread_create(&th[t], NULL, uniq_worker, (void *)t), 0);
    for (int t = 0; t < V_UNIQ_THREADS; t++) pthread_join(th[t], NULL);

    for (int t = 0; t < V_UNIQ_THREADS; t++)
        for (int i = 0; i < V_UNIQ_PER; i++)
            for (int t2 = t; t2 < V_UNIQ_THREADS; t2++)
                for (int i2 = (t2 == t ? i + 1 : 0); i2 < V_UNIQ_PER; i2++)
                    ASSERT_TRUE(g_uniq_ids[t][i] != g_uniq_ids[t2][i2]);
    vlog_close(g_uniq_v);
}

typedef struct
{
    vlog_t *v;
    const uint64_t *ids;
    size_t n_ids;
    _Atomic(int) *stop;
    int failures;
    int last_rc;
} vconc_t;

/* resolve seeded ids while a reclaim relocates them underneath; every one must stay readable
 * throughout, which is the guarantee the segmented design exists to provide */
static void *vconc_reader(void *arg)
{
    vconc_t *c = (vconc_t *)arg;
    uint8_t *want = pattern(V_MEDIUM, 61);
    for (int round = 0; round < V_CONC_ROUNDS; round++)
    {
        for (size_t i = 0; i < c->n_ids; i++)
        {
            uint8_t *got = NULL;
            size_t glen = 0;
            if (vlog_read(c->v, c->ids[i], &got, &glen) != VLOG_OK)
            {
                c->failures++;
                continue;
            }
            if (glen != V_MEDIUM || memcmp(got, want, V_MEDIUM) != 0) c->failures++;
            free(got);
        }
    }
    free(want);
    atomic_store(c->stop, 1);
    return NULL;
}

static void *vconc_writer(void *arg)
{
    vconc_t *c = (vconc_t *)arg;
    uint8_t *val = pattern(V_MEDIUM, 62);
    for (int i = 0; i < V_CONC_WRITES && !atomic_load(c->stop); i++)
    {
        vlog_id_t id = 0;
        const int rc = vlog_write(c->v, val, V_MEDIUM, NULL, 0, &id, NULL);
        if (rc != VLOG_OK)
        {
            c->failures++;
            c->last_rc = rc;
        }
    }
    free(val);
    return NULL;
}

static void *vconc_reclaimer(void *arg)
{
    vconc_t *c = (vconc_t *)arg;
    uint64_t *keep = malloc(c->n_ids * sizeof(*keep));
    memcpy(keep, c->ids, c->n_ids * sizeof(*keep));
    while (!atomic_load(c->stop))
    {
        /* only the seeded ids are ever reported live, so the writers' values are the garbage each
         * pass works through. the segments still holding a seeded value survive whatever else has
         * died in them, which is what keeps the readers reading while reclamation runs underneath
         */
        vlog_live_reset(c->v);
        for (size_t i = 0; i < c->n_ids; i++)
        {
            uint64_t segment = 0, bytes = 0;
            if (vlog_segment_of(c->v, keep[i], &segment, &bytes) == VLOG_OK)
                vlog_live_add(c->v, segment, bytes, 1);
        }
        if (vlog_reclaim(c->v) != VLOG_OK) c->failures++;

        /* descriptors are taken back while the readers are inside the store, so an eviction that
         * did not wait for a reader to leave would close a file out from under a read in flight */
        (void)vlog_evict_idle_segments(c->v, 0);
        usleep(V_CONC_RECLAIM_PAUSE_US);
    }
    free(keep);
    return NULL;
}

void test_concurrent_reads_writes_and_reclaim(void)
{
    fresh_dir();
    vlog_t *v = open_store(TDB_COMPRESS_NONE, V_CONC_SEG_TARGET);

    uint64_t ids[V_CONC_SEED];
    uint8_t *val = pattern(V_MEDIUM, 61);
    for (int i = 0; i < V_CONC_SEED; i++) ids[i] = put(v, val, V_MEDIUM);
    free(val);

    _Atomic(int) stop;
    atomic_init(&stop, 0);

    vconc_t readers[V_CONC_READERS], writers[V_CONC_WRITERS], gc;
    pthread_t rt[V_CONC_READERS], wt[V_CONC_WRITERS], gt;
    for (int i = 0; i < V_CONC_READERS; i++)
    {
        readers[i].v = v;
        readers[i].ids = ids;
        readers[i].n_ids = V_CONC_SEED;
        readers[i].stop = &stop;
        readers[i].failures = 0;
        ASSERT_EQ(pthread_create(&rt[i], NULL, vconc_reader, &readers[i]), 0);
    }
    for (int i = 0; i < V_CONC_WRITERS; i++)
    {
        writers[i].v = v;
        writers[i].ids = ids;
        writers[i].n_ids = V_CONC_SEED;
        writers[i].stop = &stop;
        writers[i].failures = 0;
        ASSERT_EQ(pthread_create(&wt[i], NULL, vconc_writer, &writers[i]), 0);
    }
    gc.v = v;
    gc.ids = ids;
    gc.n_ids = V_CONC_SEED;
    gc.stop = &stop;
    gc.failures = 0;
    ASSERT_EQ(pthread_create(&gt, NULL, vconc_reclaimer, &gc), 0);

    for (int i = 0; i < V_CONC_READERS; i++) pthread_join(rt[i], NULL);
    for (int i = 0; i < V_CONC_WRITERS; i++) pthread_join(wt[i], NULL);
    pthread_join(gt, NULL);

    for (int i = 0; i < V_CONC_READERS; i++) ASSERT_EQ(readers[i].failures, 0);
    for (int i = 0; i < V_CONC_WRITERS; i++)
    {
        if (writers[i].failures)
        {
            vlog_stats_t st;
            (void)vlog_get_stats(v, &st);
            printf("writer %d failures=%d last_rc=%d segments=%llu file=%lluMB\n", i,
                   writers[i].failures, writers[i].last_rc, (unsigned long long)st.segment_count,
                   (unsigned long long)(st.file_size / (1024 * 1024)));
            fflush(stdout);
        }
        ASSERT_EQ(writers[i].failures, 0);
    }
    ASSERT_EQ(gc.failures, 0);
    vlog_close(v);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_open_fresh_empty, tests_passed);
    RUN_TEST(test_roundtrip_one_byte, tests_passed);
    RUN_TEST(test_roundtrip_small, tests_passed);
    RUN_TEST(test_roundtrip_medium, tests_passed);
    RUN_TEST(test_roundtrip_large, tests_passed);
    RUN_TEST(test_tight_packing, tests_passed);
    RUN_TEST(test_stats_used_bytes, tests_passed);
    RUN_TEST(test_stacked_chain_round_trips, tests_passed);
    RUN_TEST(test_mixed_codecs_in_one_store, tests_passed);
    RUN_TEST(test_compression_compressible, tests_passed);
    RUN_TEST(test_compression_incompressible, tests_passed);
    RUN_TEST(test_writes_roll_into_several_segments, tests_passed);
    RUN_TEST(test_reclaim_keeps_live_values_readable, tests_passed);
    RUN_TEST(test_reclaim_drops_dead_values, tests_passed);
    RUN_TEST(test_reclaim_leaves_the_active_segment_alone, tests_passed);
    RUN_TEST(test_reclaim_spares_what_a_builder_may_have_written, tests_passed);
    RUN_TEST(test_reclaim_floor_follows_the_builders_still_running, tests_passed);
    RUN_TEST(test_idle_segments_give_back_their_descriptors, tests_passed);
    RUN_TEST(test_a_value_larger_than_a_segment_is_not_split, tests_passed);
    RUN_TEST(test_chain_stats_follow_the_values_not_the_configuration, tests_passed);
    RUN_TEST(test_reclaim_is_idempotent, tests_passed);
    RUN_TEST(test_write_after_reclaim, tests_passed);
    RUN_TEST(test_recover_keeps_everything, tests_passed);
    RUN_TEST(test_recover_after_reclaim, tests_passed);
    RUN_TEST(test_recover_appends_to_a_fresh_segment, tests_passed);
    RUN_TEST(test_recover_torn_tail_ignored, tests_passed);
    RUN_TEST(test_read_detects_corruption, tests_passed);
    RUN_TEST(test_read_reports_corruption_when_the_chain_cannot_be_resolved, tests_passed);
    RUN_TEST(test_stats_report_reclaim_activity, tests_passed);
    RUN_TEST(test_stats_counters_are_per_handle, tests_passed);
    RUN_TEST(test_reclaim_of_an_all_dead_segment_moves_nothing, tests_passed);
    RUN_TEST(test_retire_refuses_the_segment_taking_appends, tests_passed);
    RUN_TEST(test_list_segments_reports_each, tests_passed);
    RUN_TEST(test_sync_succeeds, tests_passed);
    RUN_TEST(test_invalid_args, tests_passed);
    RUN_TEST(test_many_values_stress, tests_passed);
    RUN_TEST(test_concurrent_ids_are_unique, tests_passed);
    RUN_TEST(test_concurrent_reads_writes_and_reclaim, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
