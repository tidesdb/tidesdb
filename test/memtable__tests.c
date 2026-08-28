/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "../src/base/errors.h" /* TDB_ERR_BUSY */
#include "../src/memtable/memtable.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define MT_MAX_LEVEL   12
#define MT_PROBABILITY 0.25f

#define L0_BUFFER_SIZE (64 * 1024)
#define L0_QUEUE_SIZE  8

/* how long the drainer waits before retiring an immutable, long enough that the writer under test
 * is already parked in the admission wait when the queue drains */
#define ADMIT_DRAIN_DELAY_US 20000

/* a fresh pairing has its skip_list built, refcount 1, no writers, not flushed, and holds the id,
 * generation, and borrowed wal it was given; the skip_list is usable for a put/get round trip */
void test_memtable_create_basics(void)
{
    tidesdb_memtable_t *mt =
        tidesdb_memtable_create(NULL, 7, 3, MT_MAX_LEVEL, MT_PROBABILITY, NULL, NULL);
    ASSERT_TRUE(mt != NULL);
    ASSERT_TRUE(mt->skip_list != NULL);
    ASSERT_TRUE(atomic_load(&mt->wal) == NULL);
    ASSERT_EQ((int)mt->id, 7);
    ASSERT_EQ((int)mt->generation, 3);
    ASSERT_EQ(atomic_load(&mt->refcount), 1);
    ASSERT_EQ(atomic_load(&mt->writers), 0);
    ASSERT_EQ(atomic_load(&mt->flushed), 0);

    const uint8_t key[] = "alpha";
    const uint8_t val[] = "one";
    ASSERT_EQ(skip_list_put_with_seq(mt->skip_list, key, sizeof(key), val, sizeof(val), -1, 1, 0),
              0);

    uint8_t *out = NULL;
    size_t out_size = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;
    ASSERT_EQ(skip_list_get(mt->skip_list, key, sizeof(key), &out, &out_size, &ttl, &deleted), 0);
    ASSERT_TRUE(out != NULL && out_size == sizeof(val) && memcmp(out, val, out_size) == 0);
    ASSERT_EQ((int)deleted, 0);
    free(out);

    tidesdb_memtable_free(mt);
}

/* the pairing borrows the wal -- freeing the memtable frees the skip_list but leaves the wal open
 * and usable, since the flush path (not the memtable) owns closing it */
void test_memtable_free_leaves_wal_open(void)
{
    const char *wal_path = "./memtable_test_wal.log";
    (void)remove(wal_path);

    block_manager_t *wal = NULL;
    ASSERT_EQ(block_manager_open(&wal, wal_path, BLOCK_MANAGER_SYNC_NONE), 0);
    ASSERT_TRUE(wal != NULL);

    tidesdb_memtable_t *mt =
        tidesdb_memtable_create(wal, 1, 0, MT_MAX_LEVEL, MT_PROBABILITY, NULL, NULL);
    ASSERT_TRUE(mt != NULL);
    ASSERT_TRUE(atomic_load(&mt->wal) == wal);

    tidesdb_memtable_free(mt);

    /* the wal must still be a valid, open handle we can close ourselves without a double free */
    ASSERT_EQ(block_manager_close(wal), 0);
    (void)remove(wal_path);
}

/* freeing NULL is a no-op */
void test_memtable_free_null_safe(void)
{
    tidesdb_memtable_free(NULL);
    ASSERT_TRUE(1);
}

/* the shared L0 subsystem is created with its config stored, an empty queue, a backpressure
 * controller, and the cf-index allocator at zero; destroy is null-safe */
void test_l0_create_destroy(void)
{
    tidesdb_l0_t *l0 =
        tidesdb_l0_create(L0_BUFFER_SIZE, L0_QUEUE_SIZE, MT_MAX_LEVEL, MT_PROBABILITY, NULL, NULL);
    ASSERT_TRUE(l0 != NULL);
    ASSERT_TRUE(l0->write_buffer_size == (size_t)L0_BUFFER_SIZE);
    ASSERT_EQ(l0->l0_queue_size, L0_QUEUE_SIZE);
    ASSERT_EQ(l0->max_level, MT_MAX_LEVEL);
    ASSERT_TRUE(l0->queue != NULL);
    ASSERT_TRUE(l0->backpressure != NULL);
    ASSERT_EQ((int)atomic_load(&l0->next_cf_index), 0);

    tidesdb_l0_destroy(l0);
    tidesdb_l0_destroy(NULL);
}

/* cf-index allocation hands out a fresh, monotonically increasing index each time */
void test_l0_cf_index_alloc(void)
{
    tidesdb_l0_t *l0 =
        tidesdb_l0_create(L0_BUFFER_SIZE, L0_QUEUE_SIZE, MT_MAX_LEVEL, MT_PROBABILITY, NULL, NULL);
    ASSERT_TRUE(l0 != NULL);
    ASSERT_EQ((int)tidesdb_l0_cf_index_alloc(l0), 0);
    ASSERT_EQ((int)tidesdb_l0_cf_index_alloc(l0), 1);
    ASSERT_EQ((int)tidesdb_l0_cf_index_alloc(l0), 2);
    tidesdb_l0_destroy(l0);
}

/* on reopen, observing indices recovered from manifests raises the allocator floor so a later alloc
 * never collides with an index already in use; observing a lower index does not lower the floor */
void test_l0_cf_index_observe_reconstruction(void)
{
    tidesdb_l0_t *l0 =
        tidesdb_l0_create(L0_BUFFER_SIZE, L0_QUEUE_SIZE, MT_MAX_LEVEL, MT_PROBABILITY, NULL, NULL);
    ASSERT_TRUE(l0 != NULL);

    /* manifests declared cf-indices 0, 3, 1 in some scan order */
    tidesdb_l0_cf_index_observe(l0, 0);
    tidesdb_l0_cf_index_observe(l0, 3);
    tidesdb_l0_cf_index_observe(l0, 1);
    ASSERT_EQ((int)tidesdb_l0_cf_index_alloc(l0), 4);

    /* a later observe of an already-covered index must not pull the floor back down */
    tidesdb_l0_cf_index_observe(l0, 2);
    ASSERT_EQ((int)tidesdb_l0_cf_index_alloc(l0), 5);

    tidesdb_l0_cf_index_observe(NULL, 9); /* null-safe */
    tidesdb_l0_destroy(l0);
}

/* build an L0 with a fresh active memtable backed by a real WAL at wal_path; the caller closes the
 * returned wal and destroys l0 */
static tidesdb_l0_t *l0_with_active_wal(const char *wal_path, block_manager_t **out_wal)
{
    (void)remove(wal_path);
    block_manager_t *wal = NULL;
    if (block_manager_open(&wal, wal_path, BLOCK_MANAGER_SYNC_NONE) != 0) return NULL;
    tidesdb_l0_t *l0 =
        tidesdb_l0_create(L0_BUFFER_SIZE, L0_QUEUE_SIZE, MT_MAX_LEVEL, MT_PROBABILITY, NULL, NULL);
    if (!l0)
    {
        block_manager_close(wal);
        return NULL;
    }
    tidesdb_memtable_t *mt =
        tidesdb_memtable_create(wal, 0, 0, MT_MAX_LEVEL, MT_PROBABILITY, NULL, NULL);
    if (!mt)
    {
        tidesdb_l0_destroy(l0);
        block_manager_close(wal);
        return NULL;
    }
    tidesdb_l0_set_active(l0, mt);
    *out_wal = wal;
    return l0;
}

/* a put appends to the WAL before applying, and a get reads it back; the WAL genuinely grows,
 * proving the record is durable before it is visible */
void test_l0_put_get_roundtrip(void)
{
    const char *wal_path = "./l0_test_put.wal";
    block_manager_t *wal = NULL;
    tidesdb_l0_t *l0 = l0_with_active_wal(wal_path, &wal);
    ASSERT_TRUE(l0 != NULL);

    int blocks_before = block_manager_count_blocks(wal);

    const uint8_t key[] = "alpha";
    const uint8_t val[] = "one";
    ASSERT_EQ(tidesdb_l0_put(l0, 0, key, sizeof(key), val, sizeof(val), -1, 1, 0), TDB_SUCCESS);

    /* the WAL grew by exactly one record before the value became visible */
    ASSERT_EQ(block_manager_count_blocks(wal), blocks_before + 1);

    uint8_t *out = NULL;
    size_t out_size = 0;
    int64_t ttl = 0;
    uint8_t deleted = 1;
    ASSERT_EQ(tidesdb_l0_get(l0, 0, key, sizeof(key), &out, &out_size, &ttl, &deleted),
              TDB_SUCCESS);
    ASSERT_TRUE(out != NULL && out_size == sizeof(val) && memcmp(out, val, out_size) == 0);
    ASSERT_EQ((int)deleted, 0);
    free(out);

    /* an absent key is not found */
    out = NULL;
    ASSERT_EQ(tidesdb_l0_get(l0, 0, (const uint8_t *)"missing", 8, &out, &out_size, &ttl, &deleted),
              TDB_ERR_NOT_FOUND);

    tidesdb_l0_destroy(l0);
    block_manager_close(wal);
    (void)remove(wal_path);
}

/* the cf-index prefix isolates column families sharing the one L0: the same key under two
 * cf-indices is two distinct entries with distinct values */
void test_l0_prefix_isolation(void)
{
    const char *wal_path = "./l0_test_prefix.wal";
    block_manager_t *wal = NULL;
    tidesdb_l0_t *l0 = l0_with_active_wal(wal_path, &wal);
    ASSERT_TRUE(l0 != NULL);

    const uint8_t key[] = "shared";
    const uint8_t v0[] = "cf0-value";
    const uint8_t v1[] = "cf1-value";
    ASSERT_EQ(tidesdb_l0_put(l0, 0, key, sizeof(key), v0, sizeof(v0), -1, 1, 0), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_l0_put(l0, 1, key, sizeof(key), v1, sizeof(v1), -1, 2, 0), TDB_SUCCESS);

    uint8_t *out = NULL;
    size_t out_size = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;
    ASSERT_EQ(tidesdb_l0_get(l0, 0, key, sizeof(key), &out, &out_size, &ttl, &deleted),
              TDB_SUCCESS);
    ASSERT_TRUE(out_size == sizeof(v0) && memcmp(out, v0, out_size) == 0);
    free(out);

    out = NULL;
    ASSERT_EQ(tidesdb_l0_get(l0, 1, key, sizeof(key), &out, &out_size, &ttl, &deleted),
              TDB_SUCCESS);
    ASSERT_TRUE(out_size == sizeof(v1) && memcmp(out, v1, out_size) == 0);
    free(out);

    tidesdb_l0_destroy(l0);
    block_manager_close(wal);
    (void)remove(wal_path);
}

/* a tombstone put is a present entry that reads back with the deleted flag set */
void test_l0_tombstone(void)
{
    const char *wal_path = "./l0_test_tomb.wal";
    block_manager_t *wal = NULL;
    tidesdb_l0_t *l0 = l0_with_active_wal(wal_path, &wal);
    ASSERT_TRUE(l0 != NULL);

    const uint8_t key[] = "gone";
    ASSERT_EQ(tidesdb_l0_put(l0, 0, key, sizeof(key), NULL, 0, -1, 3, SKIP_LIST_FLAG_DELETED),
              TDB_SUCCESS);

    uint8_t *out = NULL;
    size_t out_size = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;
    ASSERT_EQ(tidesdb_l0_get(l0, 0, key, sizeof(key), &out, &out_size, &ttl, &deleted),
              TDB_SUCCESS);
    ASSERT_EQ((int)deleted, 1);
    free(out);

    tidesdb_l0_destroy(l0);
    block_manager_close(wal);
    (void)remove(wal_path);
}

/* an all-in-memory L0 with a NULL-wal active memtable, for exercising rotation without WAL files */
static tidesdb_l0_t *l0_in_memory(size_t buffer_size)
{
    tidesdb_l0_t *l0 =
        tidesdb_l0_create(buffer_size, L0_QUEUE_SIZE, MT_MAX_LEVEL, MT_PROBABILITY, NULL, NULL);
    if (!l0) return NULL;
    tidesdb_memtable_t *mt =
        tidesdb_memtable_create(NULL, 0, 0, MT_MAX_LEVEL, MT_PROBABILITY, NULL, NULL);
    if (!mt)
    {
        tidesdb_l0_destroy(l0);
        return NULL;
    }
    tidesdb_l0_set_active(l0, mt);
    return l0;
}

static tidesdb_memtable_t *fresh_mt(uint64_t id)
{
    return tidesdb_memtable_create(NULL, id, id, MT_MAX_LEVEL, MT_PROBABILITY, NULL, NULL);
}

static int mt_put(tidesdb_l0_t *l0, const char *key, const char *val, uint64_t seq)
{
    return tidesdb_l0_put(l0, 0, (const uint8_t *)key, strlen(key) + 1, (const uint8_t *)val,
                          strlen(val) + 1, -1, seq, 0);
}

/* a rotation seals the active into the queue; the sealed data reads back as an immutable while new
 * writes land in the fresh active */
void test_l0_rotate_and_read(void)
{
    tidesdb_l0_t *l0 = l0_in_memory(L0_BUFFER_SIZE);
    ASSERT_TRUE(l0 != NULL);

    ASSERT_EQ(mt_put(l0, "A", "value-a", 1), TDB_SUCCESS);
    ASSERT_EQ((int)tidesdb_l0_queue_depth(l0), 0);

    ASSERT_EQ(tidesdb_l0_rotate(l0, fresh_mt(1)), TDB_SUCCESS);
    ASSERT_EQ((int)tidesdb_l0_queue_depth(l0), 1);

    ASSERT_EQ(mt_put(l0, "B", "value-b", 2), TDB_SUCCESS);

    uint8_t *out = NULL;
    size_t out_size = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;
    /* A now lives only in the sealed immutable, B in the fresh active */
    ASSERT_EQ(tidesdb_l0_get(l0, 0, (const uint8_t *)"A", 2, &out, &out_size, &ttl, &deleted),
              TDB_SUCCESS);
    ASSERT_TRUE(memcmp(out, "value-a", out_size) == 0);
    free(out);
    out = NULL;
    ASSERT_EQ(tidesdb_l0_get(l0, 0, (const uint8_t *)"B", 2, &out, &out_size, &ttl, &deleted),
              TDB_SUCCESS);
    ASSERT_TRUE(memcmp(out, "value-b", out_size) == 0);
    free(out);
    out = NULL;
    ASSERT_EQ(tidesdb_l0_get(l0, 0, (const uint8_t *)"Z", 2, &out, &out_size, &ttl, &deleted),
              TDB_ERR_NOT_FOUND);

    tidesdb_l0_destroy(l0);
}

/* a key present in more than one memtable resolves to the newest copy -- active over immutable, and
 * a newer immutable over an older one */
void test_l0_newest_version_wins(void)
{
    tidesdb_l0_t *l0 = l0_in_memory(L0_BUFFER_SIZE);
    ASSERT_TRUE(l0 != NULL);

    ASSERT_EQ(mt_put(l0, "K", "v1", 1), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_l0_rotate(l0, fresh_mt(1)), TDB_SUCCESS); /* imm1: K=v1 */
    ASSERT_EQ(mt_put(l0, "K", "v2", 2), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_l0_rotate(l0, fresh_mt(2)), TDB_SUCCESS); /* imm2: K=v2, active empty */

    uint8_t *out = NULL;
    size_t out_size = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;
    /* both immutables hold K; the newer one (v2) wins on a newest-first walk */
    ASSERT_EQ(tidesdb_l0_get(l0, 0, (const uint8_t *)"K", 2, &out, &out_size, &ttl, &deleted),
              TDB_SUCCESS);
    ASSERT_TRUE(memcmp(out, "v2", out_size) == 0);
    free(out);

    /* a fresh write to the active shadows both immutables */
    ASSERT_EQ(mt_put(l0, "K", "v3", 3), TDB_SUCCESS);
    out = NULL;
    ASSERT_EQ(tidesdb_l0_get(l0, 0, (const uint8_t *)"K", 2, &out, &out_size, &ttl, &deleted),
              TDB_SUCCESS);
    ASSERT_TRUE(memcmp(out, "v3", out_size) == 0);
    free(out);

    tidesdb_l0_destroy(l0);
}

/* the read walks the active memtable first and the immutables newest to oldest, taking the first
 * hit rather than the highest sequence -- so a version in the active shadows a newer one behind it.
 * the ordering that makes the walk right is a property of the write path, not of this read, and
 * only a commit whose sequence was drawn before a rotation and applied after it can break it. this
 * pins what such a break costs, since nothing here detects one */
void test_l0_active_shadows_a_newer_immutable(void)
{
    tidesdb_l0_t *l0 = l0_in_memory(L0_BUFFER_SIZE);
    ASSERT_TRUE(l0 != NULL);

    ASSERT_EQ(mt_put(l0, "K", "newer", 10), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_l0_rotate(l0, fresh_mt(1)), TDB_SUCCESS); /* imm holds K at seq 10 */
    ASSERT_EQ(mt_put(l0, "K", "stale", 5), TDB_SUCCESS);        /* active holds K at seq 5 */

    uint8_t *out = NULL;
    size_t out_size = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;
    ASSERT_EQ(tidesdb_l0_get(l0, 0, (const uint8_t *)"K", 2, &out, &out_size, &ttl, &deleted),
              TDB_SUCCESS);
    ASSERT_TRUE(memcmp(out, "stale", out_size) == 0);
    free(out);

    tidesdb_l0_destroy(l0);
}

/* the same walk across two immutables -- the one rotated later is read first and wins, whatever
 * sequence each holds */
void test_l0_a_later_immutable_shadows_a_newer_earlier_one(void)
{
    tidesdb_l0_t *l0 = l0_in_memory(L0_BUFFER_SIZE);
    ASSERT_TRUE(l0 != NULL);

    ASSERT_EQ(mt_put(l0, "K", "newer", 10), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_l0_rotate(l0, fresh_mt(1)), TDB_SUCCESS);
    ASSERT_EQ(mt_put(l0, "K", "stale", 5), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_l0_rotate(l0, fresh_mt(2)), TDB_SUCCESS);

    uint8_t *out = NULL;
    size_t out_size = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;
    ASSERT_EQ(tidesdb_l0_get(l0, 0, (const uint8_t *)"K", 2, &out, &out_size, &ttl, &deleted),
              TDB_SUCCESS);
    ASSERT_TRUE(memcmp(out, "stale", out_size) == 0);
    free(out);

    tidesdb_l0_destroy(l0);
}

/* immutables dequeue oldest first, and reclaiming a dequeued one frees it and shrinks the queue */
void test_l0_dequeue_fifo_and_reclaim(void)
{
    tidesdb_l0_t *l0 = l0_in_memory(L0_BUFFER_SIZE);
    ASSERT_TRUE(l0 != NULL);

    ASSERT_EQ(mt_put(l0, "first", "1", 1), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_l0_rotate(l0, fresh_mt(1)), TDB_SUCCESS);
    ASSERT_EQ(mt_put(l0, "second", "2", 2), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_l0_rotate(l0, fresh_mt(2)), TDB_SUCCESS);
    ASSERT_EQ((int)tidesdb_l0_queue_depth(l0), 2);

    tidesdb_memtable_t *oldest = tidesdb_l0_dequeue_immutable(l0);
    ASSERT_TRUE(oldest != NULL);
    ASSERT_EQ((int)oldest->id, 0); /* the very first active, sealed first */
    tidesdb_memtable_mark_flushed(oldest);
    ASSERT_EQ(atomic_load(&oldest->flushed), 1);
    tidesdb_l0_reclaim(l0, oldest);
    ASSERT_EQ((int)tidesdb_l0_queue_depth(l0), 1);

    tidesdb_memtable_t *next = tidesdb_l0_dequeue_immutable(l0);
    ASSERT_TRUE(next != NULL);
    ASSERT_EQ((int)next->id, 1);
    tidesdb_l0_reclaim(l0, next);
    ASSERT_EQ((int)tidesdb_l0_queue_depth(l0), 0);
    ASSERT_TRUE(tidesdb_l0_dequeue_immutable(l0) == NULL);

    tidesdb_l0_destroy(l0);
}

/* the rotation counter exists so a read that spans the active and the queue non-atomically can tell
 * the reader-visible set moved under it and retry instead of reporting a false absence. a rotation
 * is one way that set moves; retiring a flushed immutable is the other, and it removes a memtable a
 * reader may be about to look in. both have to be observable to a bracketed reader, or a read that
 * misses the active and then finds the immutable already retired reports a definitive not-found it
 * has no right to */

/* a reclaim must not block the caller while a reader still holds the immutable. the flush path
 * calls it under locks a create or drop needs, so an unbounded wait there is what turns one slow
 * reader into a database-wide ddl stall. it defers instead, and the deferred immutable is freed by
 * a later sweep once the reader lets go */
/* the reclaim gate is the database-wide reader epoch, not just the immutable's own reference count,
 * so an unrelated read anywhere in the database holds every immutable back. under a load that keeps
 * that epoch occupied it never reads zero, and a reclaim that waited for it would never return --
 * with the flush that called it holding the column-family registry read lock throughout */
void test_l0_reclaim_defers_while_the_shared_epoch_is_occupied(void)
{
    tidesdb_l0_t *l0 = l0_in_memory(L0_BUFFER_SIZE);
    ASSERT_TRUE(l0 != NULL);

    ASSERT_EQ(mt_put(l0, "K", "v", 1), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_l0_rotate(l0, fresh_mt(1)), TDB_SUCCESS);

    tidesdb_memtable_t *claimed = tidesdb_l0_claim_immutable(l0);
    ASSERT_TRUE(claimed != NULL);

    /* stand inside the epoch exactly as a reader in any column family would */
    tdb_epoch_enter(&l0->active_readers);
    ASSERT_TRUE(tdb_epoch_active(&l0->active_readers) > 0);

    tidesdb_l0_retire_immutable(l0, claimed);
    ASSERT_EQ((int)tidesdb_l0_queue_depth(l0), 0);

    /* still occupied, so the sweep frees nothing and the immutable is intact */
    tidesdb_l0_reclaim_pending(l0);
    ASSERT_EQ((int)tidesdb_l0_queue_depth(l0), 0);

    tdb_epoch_exit(&l0->active_readers);
    tidesdb_l0_reclaim_pending(l0);

    tidesdb_l0_destroy(l0);
}

void test_l0_reclaim_defers_rather_than_blocking(void)
{
    tidesdb_l0_t *l0 = l0_in_memory(L0_BUFFER_SIZE);
    ASSERT_TRUE(l0 != NULL);

    ASSERT_EQ(mt_put(l0, "K", "v", 1), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_l0_rotate(l0, fresh_mt(1)), TDB_SUCCESS);

    tidesdb_memtable_t *claimed = tidesdb_l0_claim_immutable(l0);
    ASSERT_TRUE(claimed != NULL);

    /* stand in for a reader still inside the immutable, taken before the retire so the reclaim the
     * retire performs is the one that has to cope with it. this is exactly the shape a flush hits:
     * it finishes with an immutable a reader has not let go of yet */
    atomic_fetch_add(&claimed->refcount, 1);

    /* the retire reclaims internally, and must return rather than wait the reference out -- it runs
     * under locks a create or drop needs */
    tidesdb_l0_retire_immutable(l0, claimed);
    ASSERT_EQ((int)tidesdb_l0_queue_depth(l0), 0);

    /* a sweep while the reference is held frees nothing, so the immutable is still intact */
    tidesdb_l0_reclaim_pending(l0);
    ASSERT_TRUE(atomic_load(&claimed->refcount) > 1);

    /* once the reader leaves, the next sweep frees it; nothing may touch it after this */
    atomic_fetch_sub(&claimed->refcount, 1);
    tidesdb_l0_reclaim_pending(l0);

    tidesdb_l0_destroy(l0);
}

void test_l0_retire_is_observable_to_a_bracketed_read(void)
{
    tidesdb_l0_t *l0 = l0_in_memory(L0_BUFFER_SIZE);
    ASSERT_TRUE(l0 != NULL);

    ASSERT_EQ(mt_put(l0, "K", "v", 1), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_l0_rotate(l0, fresh_mt(1)), TDB_SUCCESS);
    ASSERT_EQ((int)tidesdb_l0_queue_depth(l0), 1);

    /* the key now lives only in the sealed immutable, so a reader must fall through to it */
    uint8_t *out = NULL;
    size_t out_size = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;
    ASSERT_EQ(tidesdb_l0_get(l0, 0, (const uint8_t *)"K", 2, &out, &out_size, &ttl, &deleted),
              TDB_SUCCESS);
    free(out);

    tidesdb_memtable_t *claimed = tidesdb_l0_claim_immutable(l0);
    ASSERT_TRUE(claimed != NULL);
    ASSERT_EQ((int)tidesdb_l0_queue_depth(l0), 1); /* a claim leaves it reader-visible */

    const uint64_t before = atomic_load(&l0->visible_changes);
    tidesdb_l0_retire_immutable(l0, claimed);
    ASSERT_EQ((int)tidesdb_l0_queue_depth(l0), 0);

    /* the retire took a memtable out of the reader-visible set, so a reader bracketing that change
     * has to be able to see that it happened */
    ASSERT_TRUE(atomic_load(&l0->visible_changes) != before);

    tidesdb_l0_destroy(l0);
}

/* the active reports full once its byte size crosses the buffer threshold; a zero buffer never
 * fills */
void test_l0_active_full(void)
{
    tidesdb_l0_t *l0 = l0_in_memory(64);
    ASSERT_TRUE(l0 != NULL);
    ASSERT_EQ(tidesdb_l0_active_full(l0), 0);
    for (int i = 0; i < 8; i++)
    {
        char key[16];
        snprintf(key, sizeof(key), "key%02d", i);
        ASSERT_EQ(mt_put(l0, key, "some-value-bytes", (uint64_t)(i + 1)), TDB_SUCCESS);
    }
    ASSERT_EQ(tidesdb_l0_active_full(l0), 1);
    tidesdb_l0_destroy(l0);

    tidesdb_l0_t *unbounded = l0_in_memory(0);
    ASSERT_TRUE(unbounded != NULL);
    ASSERT_EQ(mt_put(unbounded, "k", "v", 1), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_l0_active_full(unbounded), 0); /* zero buffer never fills */
    tidesdb_l0_destroy(unbounded);
}

/* a WAL file name is the zero-padded generation with the .log extension, and a tight buffer is
 * refused rather than truncated */
void test_wal_filename(void)
{
    char name[32];
    ASSERT_EQ(tidesdb_wal_filename(42, name, sizeof(name)), TDB_SUCCESS);
    ASSERT_TRUE(strcmp(name, "0000042.log") == 0);
    ASSERT_EQ(tidesdb_wal_filename(0, name, sizeof(name)), TDB_SUCCESS);
    ASSERT_TRUE(strcmp(name, "0000000.log") == 0);

    char tiny[4];
    ASSERT_EQ(tidesdb_wal_filename(1, tiny, sizeof(tiny)), TDB_ERR_INVALID_ARGS);
}

/* ===== concurrent stress: rotate + read + reclaim racing ===== */

#define STRESS_WRITERS     3
#define STRESS_READERS     4
#define STRESS_KEYS        256
#define STRESS_WRITER_OPS  4000
#define STRESS_READER_OPS  6000
#define STRESS_PUT_RETRIES 8

typedef struct
{
    tidesdb_l0_t *l0;
    _Atomic(uint64_t) *seq;
    _Atomic(int) *running;
    int ops;
} stress_ctx_t;

static void *stress_writer(void *arg)
{
    stress_ctx_t *c = arg;
    for (int i = 0; i < c->ops; i++)
    {
        char key[16], val[24];
        snprintf(key, sizeof(key), "k%04d", i % STRESS_KEYS);
        snprintf(val, sizeof(val), "v%d", i);
        const uint64_t s = atomic_fetch_add(c->seq, 1) + 1;
        /* a rotation can transiently return BUSY; retry a bounded number of times */
        for (int r = 0; r < STRESS_PUT_RETRIES; r++)
        {
            const int rc = tidesdb_l0_put(c->l0, 0, (const uint8_t *)key, strlen(key) + 1,
                                          (const uint8_t *)val, strlen(val) + 1, -1, s, 0);
            if (rc != TDB_ERR_BUSY) break;
        }
    }
    return NULL;
}

static void *stress_reader(void *arg)
{
    stress_ctx_t *c = arg;
    for (int i = 0; i < c->ops; i++)
    {
        char key[16];
        snprintf(key, sizeof(key), "k%04d", i % STRESS_KEYS);
        uint8_t *out = NULL;
        size_t out_size = 0;
        int64_t ttl = 0;
        uint8_t deleted = 0;
        if (tidesdb_l0_get(c->l0, 0, (const uint8_t *)key, strlen(key) + 1, &out, &out_size, &ttl,
                           &deleted) == TDB_SUCCESS)
            free(out);
    }
    return NULL;
}

static void *stress_rotator(void *arg)
{
    stress_ctx_t *c = arg;
    uint64_t id = 1;
    while (atomic_load(c->running))
    {
        tidesdb_memtable_t *mt = fresh_mt(id++);
        if (mt) tidesdb_l0_rotate(c->l0, mt);
        usleep(150); /* let writes accumulate between rotations */
    }
    return NULL;
}

static void *stress_flusher(void *arg)
{
    stress_ctx_t *c = arg;
    for (;;)
    {
        tidesdb_memtable_t *mt = tidesdb_l0_dequeue_immutable(c->l0);
        if (mt)
        {
            tidesdb_memtable_mark_flushed(mt);
            tidesdb_l0_reclaim(c->l0,
                               mt); /* frees under concurrent readers -- the race under test */
        }
        else if (!atomic_load(c->running))
            break; /* stop only once writers/readers are done and the queue is drained */
        else
            usleep(80);
    }
    return NULL;
}

/* writers, readers, a rotator, and a flusher all race on one L0; the reader-pinned reclamation must
 * keep every read memory-safe (verified clean under ASan and TSan) */
void test_l0_concurrent_rotate_read_reclaim(void)
{
    tidesdb_l0_t *l0 = l0_in_memory(0); /* rotator drives rotation, not the size trigger */
    ASSERT_TRUE(l0 != NULL);

    _Atomic(uint64_t) seq = 0;
    _Atomic(int) running = 1;
    stress_ctx_t ctx = {.l0 = l0, .seq = &seq, .running = &running, .ops = 0};

    pthread_t writers[STRESS_WRITERS], readers[STRESS_READERS], rotator, flusher;
    stress_ctx_t wctx = ctx;
    wctx.ops = STRESS_WRITER_OPS;
    stress_ctx_t rctx = ctx;
    rctx.ops = STRESS_READER_OPS;

    for (int i = 0; i < STRESS_WRITERS; i++)
        pthread_create(&writers[i], NULL, stress_writer, &wctx);
    for (int i = 0; i < STRESS_READERS; i++)
        pthread_create(&readers[i], NULL, stress_reader, &rctx);
    pthread_create(&rotator, NULL, stress_rotator, &ctx);
    pthread_create(&flusher, NULL, stress_flusher, &ctx);

    for (int i = 0; i < STRESS_WRITERS; i++) pthread_join(writers[i], NULL);
    for (int i = 0; i < STRESS_READERS; i++) pthread_join(readers[i], NULL);

    /* stop the background threads; the flusher drains the remaining queue before it returns */
    atomic_store(&running, 0);
    pthread_join(rotator, NULL);
    pthread_join(flusher, NULL);

    ASSERT_EQ((int)tidesdb_l0_queue_depth(l0), 0); /* the flusher drained every sealed immutable */
    tidesdb_l0_destroy(l0);
}

/* a claim is one-way, so a flush that fails must release it or no worker can ever take that
 * immutable again; releasing returns it to the claimable set and balances the in-flight count */
void test_l0_release_immutable_allows_reclaim(void)
{
    tidesdb_l0_t *l0 = l0_in_memory(L0_BUFFER_SIZE);
    ASSERT_TRUE(l0 != NULL);
    ASSERT_EQ(tidesdb_l0_rotate(l0, fresh_mt(1)), TDB_SUCCESS);

    tidesdb_memtable_t *claimed = tidesdb_l0_claim_immutable(l0);
    ASSERT_TRUE(claimed != NULL);
    ASSERT_EQ(atomic_load(&l0->flushes_in_flight), 1);

    /* a second worker cannot take the same immutable while the first holds the claim */
    ASSERT_TRUE(tidesdb_l0_claim_immutable(l0) == NULL);

    tidesdb_l0_release_immutable(l0, claimed);
    ASSERT_EQ(atomic_load(&l0->flushes_in_flight), 0);

    /* the retry can now win the same immutable, and it is still queued and readable */
    tidesdb_memtable_t *retried = tidesdb_l0_claim_immutable(l0);
    ASSERT_TRUE(retried == claimed);
    ASSERT_EQ((int)tidesdb_l0_queue_depth(l0), 1);

    tidesdb_l0_destroy(l0);
}

/* rotate until the immutable queue reaches depth, so a test can put L0 at a chosen fill */
static void l0_fill_queue_to(tidesdb_l0_t *l0, int depth)
{
    for (int i = 1; i <= depth; i++)
        ASSERT_EQ(tidesdb_l0_rotate(l0, fresh_mt((uint64_t)i)), TDB_SUCCESS);
    ASSERT_EQ((int)tidesdb_l0_queue_depth(l0), depth);
}

/* an empty queue has no backlog, so admission passes the writer through without a decision */
void test_l0_admit_write_admits_with_no_backlog(void)
{
    tidesdb_l0_t *l0 = l0_in_memory(L0_BUFFER_SIZE);
    ASSERT_TRUE(l0 != NULL);

    ASSERT_EQ(tidesdb_l0_admit_write(l0), TDB_SUCCESS);

    tidesdb_l0_admission_t admission = {0};
    tidesdb_l0_admission_stats(l0, &admission);
    ASSERT_EQ((int)admission.throttled, 0);
    ASSERT_EQ((int)admission.blocked, 0);
    ASSERT_EQ((int)admission.stall_us, 0);
    tidesdb_l0_destroy(l0);
}

/* inside the throttle band the writer is admitted, but only after a dwell the counters record */
void test_l0_admit_write_throttles_inside_the_band(void)
{
    tidesdb_l0_t *l0 = l0_in_memory(L0_BUFFER_SIZE);
    ASSERT_TRUE(l0 != NULL);

    /* the default policy opens the band at three quarters of the limit */
    l0_fill_queue_to(l0, L0_QUEUE_SIZE * 3 / 4);

    ASSERT_EQ(tidesdb_l0_admit_write(l0), TDB_SUCCESS);

    tidesdb_l0_admission_t admission = {0};
    tidesdb_l0_admission_stats(l0, &admission);
    ASSERT_EQ((int)admission.throttled, 1);
    ASSERT_EQ((int)admission.blocked, 0);
    ASSERT_EQ((int)admission.ceiling_hits, 0);
    ASSERT_TRUE(admission.stall_us > 0);
    tidesdb_l0_destroy(l0);
}

/* an unbounded queue limit disables pacing entirely, however deep the queue gets */
void test_l0_admit_write_unbounded_never_paces(void)
{
    tidesdb_l0_t *l0 =
        tidesdb_l0_create(L0_BUFFER_SIZE, 0, MT_MAX_LEVEL, MT_PROBABILITY, NULL, NULL);
    ASSERT_TRUE(l0 != NULL);
    tidesdb_l0_set_active(l0, fresh_mt(0));

    l0_fill_queue_to(l0, L0_QUEUE_SIZE * 2);
    ASSERT_EQ(tidesdb_l0_admit_write(l0), TDB_SUCCESS);

    tidesdb_l0_admission_t admission = {0};
    tidesdb_l0_admission_stats(l0, &admission);
    ASSERT_EQ((int)admission.throttled, 0);
    ASSERT_EQ((int)admission.blocked, 0);
    ASSERT_EQ((int)admission.stall_us, 0);
    tidesdb_l0_destroy(l0);
}

/* drains one immutable after a delay, so a writer blocked at the peak has something to wait for */
static void *admit_drainer(void *arg)
{
    tidesdb_l0_t *l0 = (tidesdb_l0_t *)arg;
    usleep(ADMIT_DRAIN_DELAY_US);
    tidesdb_memtable_t *claimed = tidesdb_l0_claim_immutable(l0);
    if (claimed)
    {
        tidesdb_memtable_mark_flushed(claimed);
        tidesdb_l0_retire_immutable(l0, claimed);
    }
    return NULL;
}

/* at the peak the writer waits rather than dwelling, and a flush draining the queue releases it --
 * without reaching the ceiling, which would mean the wait gave up instead of being satisfied */
void test_l0_admit_write_blocks_until_the_queue_drains(void)
{
    tidesdb_l0_t *l0 = l0_in_memory(L0_BUFFER_SIZE);
    ASSERT_TRUE(l0 != NULL);

    l0_fill_queue_to(l0, L0_QUEUE_SIZE);

    pthread_t drainer;
    ASSERT_EQ(pthread_create(&drainer, NULL, admit_drainer, l0), 0);
    ASSERT_EQ(tidesdb_l0_admit_write(l0), TDB_SUCCESS);
    ASSERT_EQ(pthread_join(drainer, NULL), 0);

    tidesdb_l0_admission_t admission = {0};
    tidesdb_l0_admission_stats(l0, &admission);
    ASSERT_EQ((int)admission.blocked, 1);
    ASSERT_EQ((int)admission.ceiling_hits, 0);
    ASSERT_TRUE(admission.stall_us > 0);
    ASSERT_TRUE((int)tidesdb_l0_queue_depth(l0) < L0_QUEUE_SIZE);
    tidesdb_l0_destroy(l0);
}

/* how many records the staging-ack test appends, enough to span several ring reservations */
#define ACK_STAGE_RECORDS 256

/* acknowledging on staging returns before the flush thread has written anything, so the records
 * only reach the file because closing the WAL drains the ring. that drain is what makes the weakest
 * durability mode lose nothing to a clean shutdown, so assert every appended record is readable
 * from the reopened file */
void test_l0_wal_ack_on_stage_survives_close(void)
{
    const char *wal_path = "./l0_test_ack_stage.wal";
    (void)remove(wal_path);

    /* the reason is reported rather than only the failure. this is the one buffered open in the
     * suite, and it asks for a staging ring pair of several megabytes on top of opening the file,
     * so a refusal here can come from the allocation as easily as from the path -- and a bare
     * comparison against zero says which of them only by leaving it out */
    block_manager_t *wal = NULL;
    errno = 0;
    const int wal_rc = block_manager_open_buffered(&wal, wal_path, BLOCK_MANAGER_SYNC_NONE, 0);
    if (wal_rc != 0)
        fprintf(stderr, "buffered wal open of %s failed, errno %d (%s)\n", wal_path, errno,
                strerror(errno));
    ASSERT_EQ(wal_rc, 0);
    tidesdb_l0_t *l0 =
        tidesdb_l0_create(L0_BUFFER_SIZE, L0_QUEUE_SIZE, MT_MAX_LEVEL, MT_PROBABILITY, NULL, NULL);
    ASSERT_TRUE(l0 != NULL);
    tidesdb_l0_set_wal_ack_on_stage(l0, 1);
    tidesdb_memtable_t *mt =
        tidesdb_memtable_create(wal, 0, 0, MT_MAX_LEVEL, MT_PROBABILITY, NULL, NULL);
    ASSERT_TRUE(mt != NULL);
    tidesdb_l0_set_active(l0, mt);

    uint8_t record[64];
    memset(record, 'r', sizeof(record));
    for (int i = 0; i < ACK_STAGE_RECORDS; i++)
        ASSERT_EQ(tidesdb_l0_wal_append_one(l0, record, sizeof(record)), TDB_SUCCESS);

    tidesdb_l0_destroy(l0);
    ASSERT_EQ(block_manager_close(wal), 0);

    /* reopen the file rather than reusing the handle, so the count comes from what was written */
    block_manager_t *reopened = NULL;
    ASSERT_EQ(block_manager_open(&reopened, wal_path, BLOCK_MANAGER_SYNC_NONE), 0);
    ASSERT_EQ(block_manager_count_blocks(reopened), ACK_STAGE_RECORDS);
    ASSERT_EQ(block_manager_close(reopened), 0);
    (void)remove(wal_path);
}

/* syncing the active log takes no rotation lock, so it must work from a pin alone -- and it must
 * stay correct while other threads are committing through the same log */
void test_l0_sync_active_wal(void)
{
    const char *wal_path = "./l0_test_sync_active.wal";
    block_manager_t *wal = NULL;
    tidesdb_l0_t *l0 = l0_with_active_wal(wal_path, &wal);
    ASSERT_TRUE(l0 != NULL);

    /* an empty log syncs cleanly, and so does one with records behind it */
    ASSERT_EQ(tidesdb_l0_sync_active_wal(l0), TDB_SUCCESS);

    uint8_t record[64];
    memset(record, 's', sizeof(record));
    for (int i = 0; i < 32; i++)
        ASSERT_EQ(tidesdb_l0_wal_append_one(l0, record, sizeof(record)), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_l0_sync_active_wal(l0), TDB_SUCCESS);

    /* the records are still all there afterwards -- a sync neither drops nor duplicates any */
    ASSERT_EQ(block_manager_count_blocks(wal), 32);

    tidesdb_l0_destroy(l0);
    block_manager_close(wal);
    (void)remove(wal_path);
}

/* a NULL subsystem is rejected rather than dereferenced, so a caller on an error path may call it
 * blindly */
void test_l0_sync_active_wal_null(void)
{
    ASSERT_EQ(tidesdb_l0_sync_active_wal(NULL), TDB_ERR_INVALID_ARGS);
}

/* read one key at a snapshot ceiling, reporting only what the range tombstone tests care about --
 * whether the key resolved and whether what resolved was a delete */
static int rt_read(tidesdb_l0_t *l0, const uint32_t cf_index, const char *key,
                   const uint64_t snapshot, uint8_t *deleted)
{
    uint8_t *out = NULL;
    size_t out_size = 0;
    uint64_t vlog_id = 0;
    int64_t ttl = 0;
    uint64_t seq = 0;
    *deleted = 0;
    const int rc = tidesdb_l0_get_at_seq(l0, cf_index, (const uint8_t *)key, strlen(key), snapshot,
                                         &out, &out_size, &vlog_id, &ttl, deleted, &seq);
    free(out);
    return rc;
}

static void rt_put(tidesdb_l0_t *l0, const uint32_t cf_index, const char *key, const uint64_t seq)
{
    const uint8_t val[] = "v";
    ASSERT_EQ(tidesdb_l0_put(l0, cf_index, (const uint8_t *)key, strlen(key), val, sizeof(val), -1,
                             seq, 0),
              TDB_SUCCESS);
}

/* one range tombstone deletes every key under its prefix and leaves everything else alone */
void test_l0_range_tombstone_covers_the_prefix(void)
{
    const char *wal_path = "./l0_test_rt_cover.wal";
    block_manager_t *wal = NULL;
    tidesdb_l0_t *l0 = l0_with_active_wal(wal_path, &wal);
    ASSERT_TRUE(l0 != NULL);

    rt_put(l0, 0, "user:1", 1);
    rt_put(l0, 0, "user:2", 2);
    rt_put(l0, 0, "used", 3);
    rt_put(l0, 0, "user", 4);

    ASSERT_EQ(tidesdb_l0_apply_range_tombstone(l0, 0, (const uint8_t *)"user:", 5,
                                               (const uint8_t *)"user;", 5, 10),
              TDB_SUCCESS);

    uint8_t deleted = 0;
    ASSERT_EQ(rt_read(l0, 0, "user:1", UINT64_MAX, &deleted), TDB_SUCCESS);
    ASSERT_EQ((int)deleted, 1);
    ASSERT_EQ(rt_read(l0, 0, "user:2", UINT64_MAX, &deleted), TDB_SUCCESS);
    ASSERT_EQ((int)deleted, 1);

    /* the neighbours the bound has to exclude -- one sorting before the prefix and one that is a
     * strict prefix of it rather than a key under it */
    ASSERT_EQ(rt_read(l0, 0, "used", UINT64_MAX, &deleted), TDB_SUCCESS);
    ASSERT_EQ((int)deleted, 0);
    ASSERT_EQ(rt_read(l0, 0, "user", UINT64_MAX, &deleted), TDB_SUCCESS);
    ASSERT_EQ((int)deleted, 0);

    /* a key this memtable never held still resolves here, as a delete. that is the point of it --
     * the read stops rather than falling through to an sstable still holding an older version */
    ASSERT_EQ(rt_read(l0, 0, "user:never", UINT64_MAX, &deleted), TDB_SUCCESS);
    ASSERT_EQ((int)deleted, 1);

    tidesdb_l0_destroy(l0);
    block_manager_close(wal);
    (void)remove(wal_path);
}

/* a write after the tombstone is newer than it, so the key comes back */
void test_l0_range_tombstone_loses_to_a_newer_write(void)
{
    const char *wal_path = "./l0_test_rt_newer.wal";
    block_manager_t *wal = NULL;
    tidesdb_l0_t *l0 = l0_with_active_wal(wal_path, &wal);
    ASSERT_TRUE(l0 != NULL);

    rt_put(l0, 0, "user:1", 5);
    ASSERT_EQ(tidesdb_l0_apply_range_tombstone(l0, 0, (const uint8_t *)"user:", 5,
                                               (const uint8_t *)"user;", 5, 10),
              TDB_SUCCESS);
    rt_put(l0, 0, "user:1", 20);

    uint8_t deleted = 0;
    ASSERT_EQ(rt_read(l0, 0, "user:1", UINT64_MAX, &deleted), TDB_SUCCESS);
    ASSERT_EQ((int)deleted, 0);

    /* and at a ceiling between the two the tombstone is still what the key resolves to */
    ASSERT_EQ(rt_read(l0, 0, "user:1", 15, &deleted), TDB_SUCCESS);
    ASSERT_EQ((int)deleted, 1);

    tidesdb_l0_destroy(l0);
    block_manager_close(wal);
    (void)remove(wal_path);
}

/* a reader below the tombstone's sequence never sees it */
void test_l0_range_tombstone_is_invisible_below_its_sequence(void)
{
    const char *wal_path = "./l0_test_rt_snapshot.wal";
    block_manager_t *wal = NULL;
    tidesdb_l0_t *l0 = l0_with_active_wal(wal_path, &wal);
    ASSERT_TRUE(l0 != NULL);

    rt_put(l0, 0, "user:1", 5);
    ASSERT_EQ(tidesdb_l0_apply_range_tombstone(l0, 0, (const uint8_t *)"user:", 5,
                                               (const uint8_t *)"user;", 5, 10),
              TDB_SUCCESS);

    uint8_t deleted = 0;
    ASSERT_EQ(rt_read(l0, 0, "user:1", 9, &deleted), TDB_SUCCESS);
    ASSERT_EQ((int)deleted, 0);
    ASSERT_EQ(rt_read(l0, 0, "user:1", 10, &deleted), TDB_SUCCESS);
    ASSERT_EQ((int)deleted, 1);

    tidesdb_l0_destroy(l0);
    block_manager_close(wal);
    (void)remove(wal_path);
}

/* the tombstone is stored over the prefixed keyspace, so it can never reach another family */
void test_l0_range_tombstone_is_confined_to_its_column_family(void)
{
    const char *wal_path = "./l0_test_rt_cf.wal";
    block_manager_t *wal = NULL;
    tidesdb_l0_t *l0 = l0_with_active_wal(wal_path, &wal);
    ASSERT_TRUE(l0 != NULL);

    rt_put(l0, 0, "user:1", 1);
    rt_put(l0, 1, "user:1", 2);
    ASSERT_EQ(tidesdb_l0_apply_range_tombstone(l0, 0, (const uint8_t *)"user:", 5,
                                               (const uint8_t *)"user;", 5, 10),
              TDB_SUCCESS);

    uint8_t deleted = 0;
    ASSERT_EQ(rt_read(l0, 0, "user:1", UINT64_MAX, &deleted), TDB_SUCCESS);
    ASSERT_EQ((int)deleted, 1);
    ASSERT_EQ(rt_read(l0, 1, "user:1", UINT64_MAX, &deleted), TDB_SUCCESS);
    ASSERT_EQ((int)deleted, 0);

    tidesdb_l0_destroy(l0);
    block_manager_close(wal);
    (void)remove(wal_path);
}

/* a prefix of nothing but max bytes has its successor formed inside the family prefix itself, which
 * is the one case where a careless bound would spill into the next family */
void test_l0_range_tombstone_of_a_max_byte_prefix_stops_at_the_family(void)
{
    const char *wal_path = "./l0_test_rt_maxbyte.wal";
    block_manager_t *wal = NULL;
    tidesdb_l0_t *l0 = l0_with_active_wal(wal_path, &wal);
    ASSERT_TRUE(l0 != NULL);

    const uint8_t under[] = {0xff, 0x01};
    const uint8_t max_prefix[] = {0xff};
    const uint8_t val[] = "v";
    ASSERT_EQ(tidesdb_l0_put(l0, 0, under, sizeof(under), val, sizeof(val), -1, 1, 0), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_l0_put(l0, 1, under, sizeof(under), val, sizeof(val), -1, 2, 0), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_l0_apply_range_tombstone(l0, 0, max_prefix, sizeof(max_prefix), NULL, 0, 10),
              TDB_SUCCESS);

    uint8_t *out = NULL;
    size_t out_size = 0;
    uint64_t vlog_id = 0;
    int64_t ttl = 0;
    uint64_t seq = 0;
    uint8_t deleted = 0;
    ASSERT_EQ(tidesdb_l0_get_at_seq(l0, 0, under, sizeof(under), UINT64_MAX, &out, &out_size,
                                    &vlog_id, &ttl, &deleted, &seq),
              TDB_SUCCESS);
    ASSERT_EQ((int)deleted, 1);
    free(out);

    out = NULL;
    ASSERT_EQ(tidesdb_l0_get_at_seq(l0, 1, under, sizeof(under), UINT64_MAX, &out, &out_size,
                                    &vlog_id, &ttl, &deleted, &seq),
              TDB_SUCCESS);
    ASSERT_EQ((int)deleted, 0);
    free(out);

    tidesdb_l0_destroy(l0);
    block_manager_close(wal);
    (void)remove(wal_path);
}

/* the tombstone rotates with the memtable that took it, so a read still finds it once that memtable
 * is a sealed immutable rather than the active one */
void test_l0_range_tombstone_survives_rotation(void)
{
    tidesdb_l0_t *l0 = l0_in_memory(L0_BUFFER_SIZE);
    ASSERT_TRUE(l0 != NULL);

    rt_put(l0, 0, "user:1", 1);
    ASSERT_EQ(tidesdb_l0_apply_range_tombstone(l0, 0, (const uint8_t *)"user:", 5,
                                               (const uint8_t *)"user;", 5, 10),
              TDB_SUCCESS);

    tidesdb_memtable_t *next = fresh_mt(1);
    ASSERT_TRUE(next != NULL);
    ASSERT_EQ(tidesdb_l0_rotate(l0, next), TDB_SUCCESS);

    uint8_t deleted = 0;
    ASSERT_EQ(rt_read(l0, 0, "user:1", UINT64_MAX, &deleted), TDB_SUCCESS);
    ASSERT_EQ((int)deleted, 1);

    /* and a write into the new active memtable is newer than the sealed tombstone */
    rt_put(l0, 0, "user:1", 20);
    ASSERT_EQ(rt_read(l0, 0, "user:1", UINT64_MAX, &deleted), TDB_SUCCESS);
    ASSERT_EQ((int)deleted, 0);

    tidesdb_l0_destroy(l0);
}

void test_l0_range_tombstone_rejects_an_empty_prefix(void)
{
    tidesdb_l0_t *l0 = l0_in_memory(L0_BUFFER_SIZE);
    ASSERT_TRUE(l0 != NULL);

    ASSERT_EQ(tidesdb_l0_apply_range_tombstone(l0, 0, (const uint8_t *)"", 0, NULL, 0, 10),
              TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_l0_apply_range_tombstone(l0, 0, NULL, 4, NULL, 0, 10), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_l0_apply_range_tombstone(NULL, 0, (const uint8_t *)"a", 1, NULL, 0, 10),
              TDB_ERR_INVALID_ARGS);

    tidesdb_l0_destroy(l0);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_l0_range_tombstone_covers_the_prefix, tests_passed);
    RUN_TEST(test_l0_range_tombstone_loses_to_a_newer_write, tests_passed);
    RUN_TEST(test_l0_range_tombstone_is_invisible_below_its_sequence, tests_passed);
    RUN_TEST(test_l0_range_tombstone_is_confined_to_its_column_family, tests_passed);
    RUN_TEST(test_l0_range_tombstone_of_a_max_byte_prefix_stops_at_the_family, tests_passed);
    RUN_TEST(test_l0_range_tombstone_survives_rotation, tests_passed);
    RUN_TEST(test_l0_range_tombstone_rejects_an_empty_prefix, tests_passed);
    RUN_TEST(test_memtable_create_basics, tests_passed);
    RUN_TEST(test_memtable_free_leaves_wal_open, tests_passed);
    RUN_TEST(test_memtable_free_null_safe, tests_passed);
    RUN_TEST(test_l0_create_destroy, tests_passed);
    RUN_TEST(test_l0_cf_index_alloc, tests_passed);
    RUN_TEST(test_l0_cf_index_observe_reconstruction, tests_passed);
    RUN_TEST(test_l0_put_get_roundtrip, tests_passed);
    RUN_TEST(test_l0_prefix_isolation, tests_passed);
    RUN_TEST(test_l0_tombstone, tests_passed);
    RUN_TEST(test_l0_rotate_and_read, tests_passed);
    RUN_TEST(test_l0_newest_version_wins, tests_passed);
    RUN_TEST(test_l0_active_shadows_a_newer_immutable, tests_passed);
    RUN_TEST(test_l0_a_later_immutable_shadows_a_newer_earlier_one, tests_passed);
    RUN_TEST(test_l0_dequeue_fifo_and_reclaim, tests_passed);
    RUN_TEST(test_l0_retire_is_observable_to_a_bracketed_read, tests_passed);
    RUN_TEST(test_l0_reclaim_defers_rather_than_blocking, tests_passed);
    RUN_TEST(test_l0_reclaim_defers_while_the_shared_epoch_is_occupied, tests_passed);
    RUN_TEST(test_l0_active_full, tests_passed);
    RUN_TEST(test_wal_filename, tests_passed);
    RUN_TEST(test_l0_concurrent_rotate_read_reclaim, tests_passed);
    RUN_TEST(test_l0_release_immutable_allows_reclaim, tests_passed);
    RUN_TEST(test_l0_admit_write_admits_with_no_backlog, tests_passed);
    RUN_TEST(test_l0_admit_write_throttles_inside_the_band, tests_passed);
    RUN_TEST(test_l0_admit_write_unbounded_never_paces, tests_passed);
    RUN_TEST(test_l0_admit_write_blocks_until_the_queue_drains, tests_passed);
    RUN_TEST(test_l0_wal_ack_on_stage_survives_close, tests_passed);
    RUN_TEST(test_l0_sync_active_wal, tests_passed);
    RUN_TEST(test_l0_sync_active_wal_null, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
