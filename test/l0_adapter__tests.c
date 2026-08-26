/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "../src/base/errors.h"
#include "../src/txn/l0_adapter.h"
#include "../src/txn/mvcc.h"
#include "../src/txn/wal_record.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

/* the generation a replayed log stands for; these tests replay a single one */
#define L0_ADAPTER_TEST_GENERATION 1

#define ADP_MAX_LEVEL         12
#define ADP_PARTIAL_APPLY_SEQ 41 /* the sequence the failed batch would have committed at */
#define ADP_PROBABILITY       0.25f
#define ADP_BUFFER_SIZE       (64 * 1024)
#define ADP_QUEUE_SIZE        8

/* an in-memory L0 with a NULL-wal active memtable */
static tidesdb_l0_t *adp_l0_in_memory(void)
{
    tidesdb_l0_t *l0 = tidesdb_l0_create(ADP_BUFFER_SIZE, ADP_QUEUE_SIZE, ADP_MAX_LEVEL,
                                         ADP_PROBABILITY, NULL, NULL);
    if (!l0) return NULL;
    tidesdb_memtable_t *mt =
        tidesdb_memtable_create(NULL, 0, 0, ADP_MAX_LEVEL, ADP_PROBABILITY, NULL, NULL);
    if (!mt)
    {
        tidesdb_l0_destroy(l0);
        return NULL;
    }
    tidesdb_l0_set_active(l0, mt);
    return l0;
}

/* the read source resolves a key at a snapshot -- a version is visible only at or above its own seq
 */
void test_source_snapshot_visibility(void)
{
    tidesdb_l0_t *l0 = adp_l0_in_memory();
    ASSERT_TRUE(l0 != NULL);
    /* a committed write lands at seq 5 */
    ASSERT_EQ(tidesdb_l0_apply(l0, 0, (const uint8_t *)"k", 2, (const uint8_t *)"v5", 3, -1, 5, 0),
              TDB_SUCCESS);

    tidesdb_l0_txn_ctx_t ctx;
    ASSERT_EQ(tidesdb_l0_adapter_init(&ctx, l0, NULL), 0);
    tidesdb_source_t src;
    tidesdb_l0_source(&ctx, &src);
    ASSERT_TRUE(src.get != NULL && src.ctx == &ctx);

    tidesdb_source_version_t out;
    memset(&out, 0, sizeof(out));
    /* a later snapshot sees seq 5 */
    ASSERT_EQ(src.get(src.ctx, 0, (const uint8_t *)"k", 2, 10, &out), TDB_SOURCE_FOUND);
    ASSERT_EQ((int)out.seq, 5);
    ASSERT_TRUE(out.value != NULL && memcmp(out.value, "v5", out.value_size) == 0);
    ASSERT_EQ(out.deleted, 0);
    free(out.value);

    /* a snapshot before seq 5 does not see it */
    memset(&out, 0, sizeof(out));
    ASSERT_EQ(src.get(src.ctx, 0, (const uint8_t *)"k", 2, 3, &out), TDB_SOURCE_NOT_FOUND);

    /* an absent key is not found */
    ASSERT_EQ(src.get(src.ctx, 0, (const uint8_t *)"absent", 7, 10, &out), TDB_SOURCE_NOT_FOUND);

    tidesdb_l0_destroy(l0);
}

/* the backend durably appends a WAL batch and applies entries that then read back through the
 * source */
void test_backend_wal_append_and_apply(void)
{
    const char *wal_path = "./l0_adapter_wal.log";
    (void)remove(wal_path);
    block_manager_t *wal = NULL;
    ASSERT_EQ(block_manager_open(&wal, wal_path, BLOCK_MANAGER_SYNC_NONE), 0);

    tidesdb_l0_t *l0 = tidesdb_l0_create(ADP_BUFFER_SIZE, ADP_QUEUE_SIZE, ADP_MAX_LEVEL,
                                         ADP_PROBABILITY, NULL, NULL);
    ASSERT_TRUE(l0 != NULL);
    tidesdb_l0_set_active(
        l0, tidesdb_memtable_create(wal, 0, 0, ADP_MAX_LEVEL, ADP_PROBABILITY, NULL, NULL));

    tidesdb_l0_txn_ctx_t ctx;
    ASSERT_EQ(tidesdb_l0_adapter_init(&ctx, l0, NULL), 0);
    tidesdb_source_t src;
    tdb_txn_backend_t be;
    tidesdb_l0_source(&ctx, &src);
    tidesdb_l0_backend(&ctx, &be);
    ASSERT_TRUE(be.wal_append != NULL && be.apply != NULL && be.backpressure != NULL);

    /* an empty immutable queue has no backlog to pace against, so admission passes the writer */
    ASSERT_EQ(be.backpressure(be.ctx, 0), 0);

    /* a raw framed batch appends one durable WAL record */
    const int before = block_manager_count_blocks(wal);
    const uint8_t batch[] = {1, 2, 3, 4, 5, 6, 7, 8};
    ASSERT_EQ(be.wal_append(be.ctx, batch, sizeof(batch)), 0);
    ASSERT_EQ(block_manager_count_blocks(wal), before + 1);

    /* apply makes an entry visible through the source */
    tidesdb_wal_entry_t entry = {0};
    entry.cf_index = 0;
    entry.seq = 7;
    entry.flags = 0;
    entry.key = (const uint8_t *)"applied";
    entry.key_size = 8;
    entry.value = (const uint8_t *)"val";
    entry.value_size = 4;
    ASSERT_EQ(be.apply(be.ctx, &entry, 1), 0);

    tidesdb_source_version_t out;
    memset(&out, 0, sizeof(out));
    ASSERT_EQ(src.get(src.ctx, 0, (const uint8_t *)"applied", 8, UINT64_MAX, &out),
              TDB_SOURCE_FOUND);
    ASSERT_EQ((int)out.seq, 7);
    ASSERT_TRUE(memcmp(out.value, "val", out.value_size) == 0);
    free(out.value);

    tidesdb_l0_destroy(l0);
    block_manager_close(wal);
    (void)remove(wal_path);
}

/* a transaction committed through the backend reads back through the source, including a tombstone
 */
/* a batch that fails part way through still lands the entries it got to, but the commit path marks
 * the sequence abandoned, so a read skips those versions and a flush drops them. without that the
 * prefix of a transaction that was reported as failed becomes readable the moment the clock passes
 * its sequence, and permanent the moment it is flushed */
void test_partial_apply_entries_are_hidden(void)
{
    const char *wal_path = "./l0_adapter_partial.log";
    (void)remove(wal_path);
    block_manager_t *wal = NULL;
    ASSERT_EQ(block_manager_open(&wal, wal_path, BLOCK_MANAGER_SYNC_NONE), 0);

    tidesdb_l0_t *l0 = tidesdb_l0_create(ADP_BUFFER_SIZE, ADP_QUEUE_SIZE, ADP_MAX_LEVEL,
                                         ADP_PROBABILITY, NULL, NULL);
    ASSERT_TRUE(l0 != NULL);
    tidesdb_l0_set_active(
        l0, tidesdb_memtable_create(wal, 0, 0, ADP_MAX_LEVEL, ADP_PROBABILITY, NULL, NULL));

    tidesdb_l0_txn_ctx_t ctx;
    ASSERT_EQ(tidesdb_l0_adapter_init(&ctx, l0, NULL), 0);
    tidesdb_source_t src;
    tdb_txn_backend_t be;
    tidesdb_l0_source(&ctx, &src);
    tidesdb_l0_backend(&ctx, &be);

    /* a two-entry batch whose second entry cannot be applied. a null key is the deterministic
     * stand-in here for what fails in production -- an allocation failure inside the skip list, or
     * the active-slot pin losing every retry to rotation -- both of which return the same way from
     * the same loop, after earlier entries have already landed */
    tidesdb_wal_entry_t batch[2];
    memset(batch, 0, sizeof(batch));
    batch[0].cf_index = 0;
    batch[0].seq = ADP_PARTIAL_APPLY_SEQ;
    batch[0].key = (const uint8_t *)"first";
    batch[0].key_size = 6;
    batch[0].value = (const uint8_t *)"v";
    batch[0].value_size = 2;
    batch[1] = batch[0];
    batch[1].key = NULL;

    ASSERT_TRUE(be.apply(be.ctx, batch, 2) != 0); /* the batch as a whole failed */

    /* the first entry did land -- nothing removes it from the skip list */
    tidesdb_source_version_t out;
    memset(&out, 0, sizeof(out));
    ASSERT_EQ(src.get(src.ctx, 0, (const uint8_t *)"first", 6, UINT64_MAX, &out), TDB_SOURCE_FOUND);
    free(out.value);

    /* once the commit path abandons the sequence, that version stops being visible even to a read
     * that ignores snapshots entirely */
    be.abandon(be.ctx, ADP_PARTIAL_APPLY_SEQ);
    memset(&out, 0, sizeof(out));
    ASSERT_EQ(src.get(src.ctx, 0, (const uint8_t *)"first", 6, UINT64_MAX, &out),
              TDB_SOURCE_NOT_FOUND);

    tidesdb_l0_destroy(l0);
    block_manager_close(wal);
    (void)remove(wal_path);
}

void test_commit_end_to_end(void)
{
    tidesdb_l0_t *l0 = adp_l0_in_memory();
    ASSERT_TRUE(l0 != NULL);
    tidesdb_l0_txn_ctx_t ctx;
    ASSERT_EQ(tidesdb_l0_adapter_init(&ctx, l0, NULL), 0);
    tidesdb_source_t src;
    tdb_txn_backend_t be;
    tidesdb_l0_source(&ctx, &src);
    tidesdb_l0_backend(&ctx, &be);

    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    ASSERT_TRUE(clock != NULL);

    /* commit a put */
    tdb_txn_t *t = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);
    ASSERT_TRUE(t != NULL);
    ASSERT_EQ(tdb_txn_put(t, 0, (const uint8_t *)"key", 3, (const uint8_t *)"hello", 6, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tdb_txn_commit(t, &be, NULL, 0), TDB_SUCCESS);
    tdb_txn_free(t);

    tidesdb_source_version_t out;
    memset(&out, 0, sizeof(out));
    ASSERT_EQ(src.get(src.ctx, 0, (const uint8_t *)"key", 3, UINT64_MAX, &out), TDB_SOURCE_FOUND);
    ASSERT_TRUE(memcmp(out.value, "hello", out.value_size) == 0);
    ASSERT_EQ(out.deleted, 0);
    free(out.value);

    /* commit a delete over the same key */
    tdb_txn_t *d = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);
    ASSERT_EQ(tdb_txn_delete(d, 0, (const uint8_t *)"key", 3), TDB_SUCCESS);
    ASSERT_EQ(tdb_txn_commit(d, &be, NULL, 0), TDB_SUCCESS);
    tdb_txn_free(d);

    memset(&out, 0, sizeof(out));
    ASSERT_EQ(src.get(src.ctx, 0, (const uint8_t *)"key", 3, UINT64_MAX, &out), TDB_SOURCE_FOUND);
    ASSERT_EQ(out.deleted, 1); /* the newest version is the tombstone */
    free(out.value);

    tidesdb_mvcc_destroy(clock);
    tidesdb_l0_destroy(l0);
}

#define ADP_COMMIT_THREADS 16

typedef struct
{
    tidesdb_mvcc_t *clock;
    const tdb_txn_backend_t *be;
    int id;
    int ok;
} commit_ctx_t;

static void *commit_worker(void *arg)
{
    commit_ctx_t *c = arg;
    char key[16], val[16];
    snprintf(key, sizeof(key), "k%02d", c->id);
    snprintf(val, sizeof(val), "v%02d", c->id);
    tdb_txn_t *t = tdb_txn_begin(c->clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);
    c->ok = t &&
            tdb_txn_put(t, 0, (const uint8_t *)key, strlen(key), (const uint8_t *)val, strlen(val),
                        -1) == TDB_SUCCESS &&
            tdb_txn_commit(t, c->be, NULL, 0) == TDB_SUCCESS;
    tdb_txn_free(t);
    return NULL;
}

/* many transactions commit concurrently through the backend; every write is durable and reads
 * back, proving the append path stays correct when commits coalesce in the log's staging ring */
void test_concurrent_commits(void)
{
    tidesdb_l0_t *l0 = adp_l0_in_memory();
    ASSERT_TRUE(l0 != NULL);
    tidesdb_l0_txn_ctx_t ctx;
    ASSERT_EQ(tidesdb_l0_adapter_init(&ctx, l0, NULL), 0);
    tidesdb_source_t src;
    tdb_txn_backend_t be;
    tidesdb_l0_source(&ctx, &src);
    tidesdb_l0_backend(&ctx, &be);
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    ASSERT_TRUE(clock != NULL);

    pthread_t th[ADP_COMMIT_THREADS];
    commit_ctx_t cc[ADP_COMMIT_THREADS];
    for (int i = 0; i < ADP_COMMIT_THREADS; i++)
    {
        cc[i] = (commit_ctx_t){clock, &be, i, 0};
        pthread_create(&th[i], NULL, commit_worker, &cc[i]);
    }
    for (int i = 0; i < ADP_COMMIT_THREADS; i++) pthread_join(th[i], NULL);

    for (int i = 0; i < ADP_COMMIT_THREADS; i++)
    {
        ASSERT_EQ(cc[i].ok, 1); /* every commit succeeded */
        char key[16], val[16];
        snprintf(key, sizeof(key), "k%02d", i);
        snprintf(val, sizeof(val), "v%02d", i);
        tidesdb_source_version_t out;
        memset(&out, 0, sizeof(out));
        ASSERT_EQ(src.get(src.ctx, 0, (const uint8_t *)key, strlen(key), UINT64_MAX, &out),
                  TDB_SOURCE_FOUND);
        ASSERT_TRUE(memcmp(out.value, val, out.value_size) == 0);
        free(out.value);
    }

    tidesdb_mvcc_destroy(clock);
    tidesdb_l0_destroy(l0);
}

/* the real apply, wrapped so that it lands the first entry of a batch and then fails -- standing in
 * for the allocation failure or lost pin retry that makes the production apply return part way
 * through the same loop */
static tdb_txn_backend_t adp_real_backend;

static int adp_apply_failing_after_first(void *ctx, const tidesdb_wal_entry_t *entries, int count)
{
    if (count > 1) (void)adp_real_backend.apply(ctx, entries, 1);
    return -1;
}

/* a single-phase commit whose apply fails after the durable WAL write is reported to the caller as
 * failed, and must stay failed. the batch is already on disk in full and replay treats a write
 * batch's presence as its commitment, so the commit path records an abort naming that sequence and
 * replay leaves the batch out. without it the transaction would come back whole on the next open,
 * after its caller was told it did not commit */
void test_failed_apply_does_not_recover_from_the_wal(void)
{
    const char *wal_path = "./l0_adapter_failed_apply.log";
    (void)remove(wal_path);

    block_manager_t *wal1 = NULL;
    ASSERT_EQ(block_manager_open(&wal1, wal_path, BLOCK_MANAGER_SYNC_NONE), 0);
    tidesdb_l0_t *l0a = tidesdb_l0_create(ADP_BUFFER_SIZE, ADP_QUEUE_SIZE, ADP_MAX_LEVEL,
                                          ADP_PROBABILITY, NULL, NULL);
    ASSERT_TRUE(l0a != NULL);
    tidesdb_l0_set_active(
        l0a, tidesdb_memtable_create(wal1, 0, 0, ADP_MAX_LEVEL, ADP_PROBABILITY, NULL, NULL));
    tidesdb_l0_txn_ctx_t ctxa;
    ASSERT_EQ(tidesdb_l0_adapter_init(&ctxa, l0a, NULL), 0);
    tidesdb_l0_backend(&ctxa, &adp_real_backend);
    tdb_txn_backend_t be = adp_real_backend;
    be.apply = adp_apply_failing_after_first;

    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();
    ASSERT_TRUE(clock != NULL);

    tdb_txn_t *t = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);
    ASSERT_TRUE(t != NULL);
    ASSERT_EQ(tdb_txn_put(t, 0, (const uint8_t *)"fa1", 3, (const uint8_t *)"x", 1, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tdb_txn_put(t, 0, (const uint8_t *)"fa2", 3, (const uint8_t *)"y", 1, -1),
              TDB_SUCCESS);

    /* the caller is told the transaction did not commit */
    ASSERT_EQ(tdb_txn_commit(t, &be, NULL, 0), TDB_ERR_IO);
    ASSERT_EQ(tdb_txn_state(t), TDB_TXN_ABORTED);
    tdb_txn_free(t);

    tidesdb_l0_destroy(l0a);
    block_manager_close(wal1);

    /* the batch reached the log before apply ran, and replay applies a write batch entry by entry
     * with no commit marker to consult -- for a single-phase commit the record's presence is the
     * commitment. so the reopened database holds both keys of a transaction that failed */
    block_manager_t *wal2 = NULL;
    ASSERT_EQ(block_manager_open(&wal2, wal_path, BLOCK_MANAGER_SYNC_NONE), 0);
    tidesdb_l0_t *l0b = tidesdb_l0_create(ADP_BUFFER_SIZE, ADP_QUEUE_SIZE, ADP_MAX_LEVEL,
                                          ADP_PROBABILITY, NULL, NULL);
    ASSERT_TRUE(l0b != NULL);
    tidesdb_l0_set_active(
        l0b, tidesdb_memtable_create(wal2, 0, 0, ADP_MAX_LEVEL, ADP_PROBABILITY, NULL, NULL));
    /* recovery scans for aborts before it applies anything, because an abort can land in a later
     * generation than the batch it cancels */
    tidesdb_l0_aborted_set_t aborted = {0};
    ASSERT_EQ(tidesdb_l0_scan_aborts(wal2, &aborted), TDB_SUCCESS);
    ASSERT_EQ(aborted.count, 1);

    uint64_t replayed_max_seq = 0;
    ASSERT_EQ(tidesdb_l0_replay_wal(l0b, wal2, L0_ADAPTER_TEST_GENERATION, &aborted,
                                    &replayed_max_seq, NULL, NULL),
              TDB_SUCCESS);

    tidesdb_l0_txn_ctx_t ctxb;
    ASSERT_EQ(tidesdb_l0_adapter_init(&ctxb, l0b, NULL), 0);
    tidesdb_source_t srcb;
    tidesdb_l0_source(&ctxb, &srcb);

    /* neither key is present: the abort record cancelled the whole batch, including the entry the
     * substituted apply had already landed in the failed run */
    tidesdb_source_version_t out;
    memset(&out, 0, sizeof(out));
    ASSERT_EQ(srcb.get(srcb.ctx, 0, (const uint8_t *)"fa1", 3, UINT64_MAX, &out),
              TDB_SOURCE_NOT_FOUND);
    memset(&out, 0, sizeof(out));
    ASSERT_EQ(srcb.get(srcb.ctx, 0, (const uint8_t *)"fa2", 3, UINT64_MAX, &out),
              TDB_SOURCE_NOT_FOUND);

    tidesdb_l0_aborted_set_free(&aborted);
    tidesdb_mvcc_destroy(clock);
    tidesdb_l0_destroy(l0b);
    block_manager_close(wal2);
    (void)remove(wal_path);
}

/* a log record whose value the commit put in the value log replays back into the memtable as a
 * reference, not as a write with an empty value. the record is written by hand here, since nothing
 * on the commit path produces one yet, and what it proves is that the encoding, the replay and the
 * memtable agree on which entries carry bytes and which carry an id */
void test_wal_replay_restores_a_value_log_reference(void)
{
    const char *wal_path = "./l0_adapter_reference.log";
    (void)remove(wal_path);

    const uint64_t id = 0xfeedfaceULL;
    const size_t logical = 8192;

    block_manager_t *wal1 = NULL;
    ASSERT_EQ(block_manager_open(&wal1, wal_path, BLOCK_MANAGER_SYNC_NONE), 0);

    tidesdb_wal_entry_t in[2];
    memset(in, 0, sizeof(in));
    in[0].cf_index = 0;
    in[0].seq = 1;
    in[0].ttl = -1;
    in[0].key = (const uint8_t *)"inline";
    in[0].key_size = 6;
    in[0].value = (const uint8_t *)"here";
    in[0].value_size = 4;
    in[1].cf_index = 0;
    in[1].seq = 2;
    in[1].ttl = -1;
    in[1].flags = TDB_WAL_ENTRY_VLOG_REF;
    in[1].key = (const uint8_t *)"separated";
    in[1].key_size = 9;
    in[1].value_size = logical;
    in[1].vlog_id = id;

    const size_t need = tidesdb_wal_batch_size(TDB_WAL_KIND_WRITE_BATCH, NULL, 0, in, 2);
    uint8_t *buf = malloc(need);
    ASSERT_TRUE(buf != NULL);
    (void)tidesdb_wal_batch_encode(TDB_WAL_KIND_WRITE_BATCH, NULL, 0, in, 2, buf, need);
    block_manager_block_t *blk = block_manager_block_create(need, buf);
    ASSERT_TRUE(blk != NULL);
    ASSERT_TRUE(block_manager_block_write(wal1, blk) >= 0);
    block_manager_block_free(blk);
    free(buf);
    block_manager_close(wal1);

    block_manager_t *wal2 = NULL;
    ASSERT_EQ(block_manager_open(&wal2, wal_path, BLOCK_MANAGER_SYNC_NONE), 0);
    tidesdb_l0_t *l0 = tidesdb_l0_create(ADP_BUFFER_SIZE, ADP_QUEUE_SIZE, ADP_MAX_LEVEL,
                                         ADP_PROBABILITY, NULL, NULL);
    ASSERT_TRUE(l0 != NULL);
    tidesdb_l0_set_active(
        l0, tidesdb_memtable_create(wal2, 0, 0, ADP_MAX_LEVEL, ADP_PROBABILITY, NULL, NULL));

    uint64_t max_seq = 0;
    ASSERT_EQ(
        tidesdb_l0_replay_wal(l0, wal2, L0_ADAPTER_TEST_GENERATION, NULL, &max_seq, NULL, NULL),
        TDB_SUCCESS);
    ASSERT_EQ((int)max_seq, 2);

    /* the inline entry came back with its bytes */
    uint8_t *value = NULL;
    size_t value_size = 0;
    uint64_t got_id = 0, seq = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;
    ASSERT_EQ(tidesdb_l0_get_at_seq(l0, 0, (const uint8_t *)"inline", 6, UINT64_MAX, &value,
                                    &value_size, &got_id, &ttl, &deleted, &seq),
              TDB_SUCCESS);
    ASSERT_EQ((int)value_size, 4);
    ASSERT_TRUE(got_id == 0);
    free(value);

    /* and the referenced one came back as an id and a logical length, holding no bytes */
    value = NULL;
    value_size = 0;
    got_id = 0;
    ASSERT_EQ(tidesdb_l0_get_at_seq(l0, 0, (const uint8_t *)"separated", 9, UINT64_MAX, &value,
                                    &value_size, &got_id, &ttl, &deleted, &seq),
              TDB_SUCCESS);
    ASSERT_TRUE(value == NULL);
    ASSERT_EQ((int)value_size, (int)logical);
    ASSERT_TRUE(got_id == id);
    ASSERT_EQ((int)seq, 2);

    tidesdb_l0_destroy(l0);
    block_manager_close(wal2);
    (void)remove(wal_path);
}

/* read one key through a source, reporting whether it resolved and, when it did, whether what
 * resolved was a delete */
static int adp_read(const tidesdb_source_t *src, const char *key, int *deleted)
{
    tidesdb_source_version_t out;
    memset(&out, 0, sizeof(out));
    const tidesdb_source_result_t r =
        src->get(src->ctx, 0, (const uint8_t *)key, strlen(key), UINT64_MAX, &out);
    if (r == TDB_SOURCE_FOUND) *deleted = out.deleted;
    free(out.value);
    return r;
}

/* a committed prefix delete is one entry in the log, and replaying that log rebuilds the interval
 * rather than the keys it covered -- so a key it covers is deleted after recovery even though no
 * record of that key was ever written */
void test_wal_replay_recovers_a_prefix_delete(void)
{
    const char *wal_path = "./l0_adapter_prefix_delete.log";
    (void)remove(wal_path);

    block_manager_t *wal1 = NULL;
    ASSERT_EQ(block_manager_open(&wal1, wal_path, BLOCK_MANAGER_SYNC_NONE), 0);
    tidesdb_l0_t *l0a = tidesdb_l0_create(ADP_BUFFER_SIZE, ADP_QUEUE_SIZE, ADP_MAX_LEVEL,
                                          ADP_PROBABILITY, NULL, NULL);
    ASSERT_TRUE(l0a != NULL);
    tidesdb_l0_set_active(
        l0a, tidesdb_memtable_create(wal1, 0, 0, ADP_MAX_LEVEL, ADP_PROBABILITY, NULL, NULL));
    tidesdb_l0_txn_ctx_t ctxa;
    ASSERT_EQ(tidesdb_l0_adapter_init(&ctxa, l0a, NULL), 0);
    tdb_txn_backend_t bea;
    tidesdb_l0_backend(&ctxa, &bea);
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();

    tdb_txn_t *writes = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);
    ASSERT_EQ(tdb_txn_put(writes, 0, (const uint8_t *)"user:1", 6, (const uint8_t *)"a", 1, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tdb_txn_put(writes, 0, (const uint8_t *)"used", 4, (const uint8_t *)"b", 1, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tdb_txn_commit(writes, &bea, NULL, 0), TDB_SUCCESS);
    tdb_txn_free(writes);

    tdb_txn_t *del = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);
    ASSERT_EQ(tdb_txn_delete_prefix(del, 0, (const uint8_t *)"user:", 5), TDB_SUCCESS);
    ASSERT_EQ(tdb_txn_commit(del, &bea, NULL, 0), TDB_SUCCESS);
    tdb_txn_free(del);

    tidesdb_l0_destroy(l0a);
    block_manager_close(wal1);

    block_manager_t *wal2 = NULL;
    ASSERT_EQ(block_manager_open(&wal2, wal_path, BLOCK_MANAGER_SYNC_NONE), 0);
    tidesdb_l0_t *l0b = tidesdb_l0_create(ADP_BUFFER_SIZE, ADP_QUEUE_SIZE, ADP_MAX_LEVEL,
                                          ADP_PROBABILITY, NULL, NULL);
    ASSERT_TRUE(l0b != NULL);
    tidesdb_l0_set_active(
        l0b, tidesdb_memtable_create(wal2, 0, 0, ADP_MAX_LEVEL, ADP_PROBABILITY, NULL, NULL));

    uint64_t replayed_max_seq = 0;
    ASSERT_EQ(tidesdb_l0_replay_wal(l0b, wal2, L0_ADAPTER_TEST_GENERATION, NULL, &replayed_max_seq,
                                    NULL, NULL),
              TDB_SUCCESS);

    tidesdb_l0_txn_ctx_t ctxb;
    ASSERT_EQ(tidesdb_l0_adapter_init(&ctxb, l0b, NULL), 0);
    tidesdb_source_t src;
    tidesdb_l0_source(&ctxb, &src);

    int deleted = 0;
    ASSERT_EQ(adp_read(&src, "user:1", &deleted), TDB_SOURCE_FOUND);
    ASSERT_EQ(deleted, 1);
    ASSERT_EQ(adp_read(&src, "used", &deleted), TDB_SOURCE_FOUND);
    ASSERT_EQ(deleted, 0);

    /* a key the log never carried at all, recovered as deleted purely from the interval */
    ASSERT_EQ(adp_read(&src, "user:9", &deleted), TDB_SOURCE_FOUND);
    ASSERT_EQ(deleted, 1);

    tidesdb_l0_destroy(l0b);
    block_manager_close(wal2);
    tidesdb_mvcc_destroy(clock);
    (void)remove(wal_path);
}

/* both orders of a prefix delete and a write under it inside one transaction. the batch shares a
 * sequence, so what decides each key is which op the write set kept -- a point write is never
 * retired by a delete buffered before it, and is always retired by one buffered after it */
void test_prefix_delete_against_a_write_in_the_same_batch(void)
{
    const char *wal_path = "./l0_adapter_prefix_batch.log";
    (void)remove(wal_path);

    block_manager_t *wal = NULL;
    ASSERT_EQ(block_manager_open(&wal, wal_path, BLOCK_MANAGER_SYNC_NONE), 0);
    tidesdb_l0_t *l0 = tidesdb_l0_create(ADP_BUFFER_SIZE, ADP_QUEUE_SIZE, ADP_MAX_LEVEL,
                                         ADP_PROBABILITY, NULL, NULL);
    ASSERT_TRUE(l0 != NULL);
    tidesdb_l0_set_active(
        l0, tidesdb_memtable_create(wal, 0, 0, ADP_MAX_LEVEL, ADP_PROBABILITY, NULL, NULL));
    tidesdb_l0_txn_ctx_t ctx;
    ASSERT_EQ(tidesdb_l0_adapter_init(&ctx, l0, NULL), 0);
    tdb_txn_backend_t be;
    tidesdb_l0_backend(&ctx, &be);
    tidesdb_source_t src;
    tidesdb_l0_source(&ctx, &src);
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();

    /* delete the prefix, then write one key back under it */
    tdb_txn_t *t1 = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);
    ASSERT_EQ(tdb_txn_delete_prefix(t1, 0, (const uint8_t *)"user:", 5), TDB_SUCCESS);
    ASSERT_EQ(tdb_txn_put(t1, 0, (const uint8_t *)"user:1", 6, (const uint8_t *)"kept", 4, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tdb_txn_commit(t1, &be, NULL, 0), TDB_SUCCESS);
    tdb_txn_free(t1);

    int deleted = 0;
    ASSERT_EQ(adp_read(&src, "user:1", &deleted), TDB_SOURCE_FOUND);
    ASSERT_EQ(deleted, 0);
    ASSERT_EQ(adp_read(&src, "user:2", &deleted), TDB_SOURCE_FOUND);
    ASSERT_EQ(deleted, 1);

    /* the other order -- the delete is buffered last, so it takes the key with it */
    tdb_txn_t *t2 = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);
    ASSERT_EQ(tdb_txn_put(t2, 0, (const uint8_t *)"acct:1", 6, (const uint8_t *)"gone", 4, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tdb_txn_delete_prefix(t2, 0, (const uint8_t *)"acct:", 5), TDB_SUCCESS);
    ASSERT_EQ(tdb_txn_commit(t2, &be, NULL, 0), TDB_SUCCESS);
    tdb_txn_free(t2);

    ASSERT_EQ(adp_read(&src, "acct:1", &deleted), TDB_SOURCE_FOUND);
    ASSERT_EQ(deleted, 1);

    /* a later write of the very key that spells the prefix. it is the newer version of that one
     * key and retires nothing else the interval covers, so a dedupe matching on equal keys alone
     * would drop the delete and leave every sibling alive */
    tdb_txn_t *t3 = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);
    ASSERT_EQ(tdb_txn_delete_prefix(t3, 0, (const uint8_t *)"org:", 4), TDB_SUCCESS);
    ASSERT_EQ(tdb_txn_put(t3, 0, (const uint8_t *)"org:", 4, (const uint8_t *)"self", 4, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tdb_txn_commit(t3, &be, NULL, 0), TDB_SUCCESS);
    tdb_txn_free(t3);

    ASSERT_EQ(adp_read(&src, "org:", &deleted), TDB_SOURCE_FOUND);
    ASSERT_EQ(deleted, 0);
    ASSERT_EQ(adp_read(&src, "org:x", &deleted), TDB_SOURCE_FOUND);
    ASSERT_EQ(deleted, 1);

    tidesdb_l0_destroy(l0);
    block_manager_close(wal);
    tidesdb_mvcc_destroy(clock);
    (void)remove(wal_path);
}

/* commits durably written to a WAL are recovered into a fresh L0 by replaying the reopened file */
void test_wal_replay_recovers_commits(void)
{
    const char *wal_path = "./l0_adapter_recover.log";
    (void)remove(wal_path);

    /* phase 1 -- commit three writes durably to the WAL, then tear the L0 down */
    block_manager_t *wal1 = NULL;
    ASSERT_EQ(block_manager_open(&wal1, wal_path, BLOCK_MANAGER_SYNC_NONE), 0);
    tidesdb_l0_t *l0a = tidesdb_l0_create(ADP_BUFFER_SIZE, ADP_QUEUE_SIZE, ADP_MAX_LEVEL,
                                          ADP_PROBABILITY, NULL, NULL);
    ASSERT_TRUE(l0a != NULL);
    tidesdb_l0_set_active(
        l0a, tidesdb_memtable_create(wal1, 0, 0, ADP_MAX_LEVEL, ADP_PROBABILITY, NULL, NULL));
    tidesdb_l0_txn_ctx_t ctxa;
    ASSERT_EQ(tidesdb_l0_adapter_init(&ctxa, l0a, NULL), 0);
    tdb_txn_backend_t bea;
    tidesdb_l0_backend(&ctxa, &bea);
    tidesdb_mvcc_t *clock = tidesdb_mvcc_create();

    for (int i = 0; i < 3; i++)
    {
        char key[16], val[16];
        snprintf(key, sizeof(key), "rk%d", i);
        snprintf(val, sizeof(val), "rv%d", i);
        tdb_txn_t *t = tdb_txn_begin(clock, TDB_ISOLATION_READ_COMMITTED, NULL, 0, NULL);
        ASSERT_EQ(tdb_txn_put(t, 0, (const uint8_t *)key, strlen(key), (const uint8_t *)val,
                              strlen(val), -1),
                  TDB_SUCCESS);
        ASSERT_EQ(tdb_txn_commit(t, &bea, NULL, 0), TDB_SUCCESS);
        tdb_txn_free(t);
    }
    tidesdb_l0_destroy(l0a);
    block_manager_close(wal1); /* the WAL file persists with the three committed batches */

    /* phase 2 -- reopen the WAL into a fresh L0 and replay it, recovering every committed write */
    block_manager_t *wal2 = NULL;
    ASSERT_EQ(block_manager_open(&wal2, wal_path, BLOCK_MANAGER_SYNC_NONE), 0);
    tidesdb_l0_t *l0b = tidesdb_l0_create(ADP_BUFFER_SIZE, ADP_QUEUE_SIZE, ADP_MAX_LEVEL,
                                          ADP_PROBABILITY, NULL, NULL);
    ASSERT_TRUE(l0b != NULL);
    tidesdb_l0_set_active(
        l0b, tidesdb_memtable_create(wal2, 0, 0, ADP_MAX_LEVEL, ADP_PROBABILITY, NULL, NULL));

    uint64_t replayed_max_seq = 0;
    /* NULL stage -- this replay carries only single-phase batches, so nothing needs staging */
    ASSERT_EQ(tidesdb_l0_replay_wal(l0b, wal2, L0_ADAPTER_TEST_GENERATION, NULL, &replayed_max_seq,
                                    NULL, NULL),
              TDB_SUCCESS);
    ASSERT_TRUE(replayed_max_seq > 0); /* the three committed writes carried real sequences */

    tidesdb_l0_txn_ctx_t ctxb;
    ASSERT_EQ(tidesdb_l0_adapter_init(&ctxb, l0b, NULL), 0);
    tidesdb_source_t src;
    tidesdb_l0_source(&ctxb, &src);
    for (int i = 0; i < 3; i++)
    {
        char key[16], val[16];
        snprintf(key, sizeof(key), "rk%d", i);
        snprintf(val, sizeof(val), "rv%d", i);
        tidesdb_source_version_t out;
        memset(&out, 0, sizeof(out));
        ASSERT_EQ(src.get(src.ctx, 0, (const uint8_t *)key, strlen(key), UINT64_MAX, &out),
                  TDB_SOURCE_FOUND);
        ASSERT_TRUE(memcmp(out.value, val, out.value_size) == 0);
        free(out.value);
    }

    tidesdb_mvcc_destroy(clock);
    tidesdb_l0_destroy(l0b);
    block_manager_close(wal2);
    (void)remove(wal_path);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_source_snapshot_visibility, tests_passed);
    RUN_TEST(test_backend_wal_append_and_apply, tests_passed);
    RUN_TEST(test_commit_end_to_end, tests_passed);
    RUN_TEST(test_partial_apply_entries_are_hidden, tests_passed);
    RUN_TEST(test_concurrent_commits, tests_passed);
    RUN_TEST(test_wal_replay_restores_a_value_log_reference, tests_passed);
    RUN_TEST(test_wal_replay_recovers_commits, tests_passed);
    RUN_TEST(test_wal_replay_recovers_a_prefix_delete, tests_passed);
    RUN_TEST(test_prefix_delete_against_a_write_in_the_same_batch, tests_passed);
    RUN_TEST(test_failed_apply_does_not_recover_from_the_wal, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
