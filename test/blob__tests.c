/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include "../include/db.h"
#include "../src/column_family/column_family.h"
#include "../src/column_family/level/level_set.h"
#include "../src/compat.h"
#include "../src/engine/engine.h"
#include "../src/engine/engine_types.h"
#include "../src/sstable/sstable.h"
#include "../src/sstable/vlog_group_disk.h"
#include "../src/sstable/vlog_internal.h"
#include "../src/sstable/vlog_sidecar.h"
#include "../src/threadmanager/threadmanager.h"
#include "../src/txn/txn.h"
#include "../src/txn/wal_record.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define BLOB_DB_DIR               "." PATH_SEPARATOR "test_blob_db"
#define BLOB_CF                   "media"
#define BLOB_PLAIN_CF             "plain"
#define BLOB_MEMTABLE_BYTES       (4u << 20)
#define BLOB_LIMIT_BYTES          64u
#define BLOB_VALUE_BYTES          31u
#define BLOB_GC_SEGMENT_BYTES     1024u
#define BLOB_GC_VALUE_BYTES       (2u * BLOB_GC_SEGMENT_BYTES)
#define BLOB_RANGE_VALUE_BYTES    32u
#define BLOB_RANGE_OFFSET         7u
#define BLOB_RANGE_LENGTH         11u
#define BLOB_CORRUPT_BYTE         (BLOB_RANGE_VALUE_BYTES - 1u)
#define BLOB_CORRUPT_VALUE        0xffu
#define BLOB_RANGE_FILL           0x41u
#define BLOB_GC_FILL              0x7au
#define BLOB_ROLL_VALUE           0x11u
#define BLOB_KV_SLICE_OFFSET      2u
#define BLOB_KV_SLICE_LENGTH      3u
#define BLOB_RACE_WAIT_TICKS      1000
#define BLOB_RACE_WAIT_US         1000
#define BLOB_CHILD_FLAG           "--blob-child"
#define BLOB_PHASE_PRE_WAL        "pre-wal"
#define BLOB_PHASE_POST_WAL       "post-wal"
#define BLOB_CHILD_NTH            "0"
#define BLOB_SCRUB_LOG_NAME       "LOG"
#define BLOB_BACKUP_DIR           BLOB_DB_DIR "_backup"
#define BLOB_FOREIGN_DIR          BLOB_DB_DIR "_foreign"
#define BLOB_BACKUP_WRITERS       3u
#define BLOB_BACKUP_WRITES        32u
#define BLOB_BACKUP_VALUE_BYTES   160u
#define BLOB_BACKUP_SEGMENT_BYTES 1024u

_Static_assert(offsetof(tidesdb_open_options_t, reserved) + sizeof(uint32_t) ==
                   offsetof(tidesdb_open_options_t, blob_scrub_enabled),
               "keep the old size-tagged options prefix free of implicit tail padding");

static const char* blob_exe = NULL;

typedef struct
{
    int (*append)(void* ctx, const uint8_t* batch, size_t size);
    int decoded;
    tidesdb_wal_entry_t entry;
} blob_wal_probe_t;

typedef struct
{
    tidesdb_t* db;
    int (*append)(void* ctx, const uint8_t* batch, size_t size);
    int rc;
    vlog_stats_t before;
    vlog_stats_t after;
} blob_gc_probe_t;

/* tests run serially, so one installed WAL observer is enough and leaves the engine backend's
 * context unchanged for its apply and separator callbacks */
static blob_wal_probe_t* blob_wal_probe = NULL;
static blob_gc_probe_t* blob_gc_probe = NULL;

static int blob_probe_wal_append(void* ctx, const uint8_t* batch, size_t size)
{
    tidesdb_wal_cursor_t cursor;
    tidesdb_wal_entry_t entry;
    blob_wal_probe->decoded = tidesdb_wal_cursor_init(&cursor, batch, size);
    if (blob_wal_probe->decoded == 0)
    {
        const int next = tidesdb_wal_cursor_next(&cursor, &entry);
        blob_wal_probe->decoded = next == 1 ? 0 : -1;
        if (blob_wal_probe->decoded == 0) blob_wal_probe->entry = entry;
    }
    return blob_wal_probe->append(ctx, batch, size);
}

static int blob_force_gc_before_wal(void* ctx, const uint8_t* batch, size_t size)
{
    const uint8_t filler = 0x31;
    vlog_id_t filler_id = 0;
    blob_gc_probe->rc = vlog_get_stats(blob_gc_probe->db->vlog, &blob_gc_probe->before);
    if (blob_gc_probe->rc == VLOG_OK)
        blob_gc_probe->rc =
            vlog_write(blob_gc_probe->db->vlog, &filler, sizeof(filler), NULL, 0, &filler_id, NULL);
    if (blob_gc_probe->rc == VLOG_OK && vlog_group_limit(blob_gc_probe->db->vlog))
        ASSERT_EQ(vlog_seal_idle_groups(blob_gc_probe->db->vlog, 0, NULL), 1);
    /* the new memtable takes a floor in the successor segment. release the previous memtable's
     * floor here, while the object still has no WAL entry or L0 reference. */
    if (blob_gc_probe->rc == VLOG_OK) blob_gc_probe->rc = tidesdb_flush_memtable(blob_gc_probe->db);
    if (blob_gc_probe->rc == VLOG_OK) blob_gc_probe->rc = vlog_reclaim(blob_gc_probe->db->vlog);
    if (blob_gc_probe->rc == VLOG_OK)
        blob_gc_probe->rc = vlog_get_stats(blob_gc_probe->db->vlog, &blob_gc_probe->after);
    if (blob_gc_probe->rc != VLOG_OK) return -1;
    return blob_gc_probe->append(ctx, batch, size);
}

static void blob_install_wal_probe(tidesdb_t* db, blob_wal_probe_t* probe)
{
    probe->append = db->backend.wal_append;
    probe->decoded = -1;
    blob_wal_probe = probe;
    db->backend.wal_append = blob_probe_wal_append;
}

static void blob_remove_wal_probe(tidesdb_t* db, const blob_wal_probe_t* probe)
{
    db->backend.wal_append = probe->append;
    blob_wal_probe = NULL;
}

static void blob_install_gc_probe(tidesdb_t* db, blob_gc_probe_t* probe)
{
    probe->db = db;
    probe->append = db->backend.wal_append;
    probe->rc = VLOG_ERR_INVALID;
    blob_gc_probe = probe;
    db->backend.wal_append = blob_force_gc_before_wal;
}

static void blob_remove_gc_probe(tidesdb_t* db, const blob_gc_probe_t* probe)
{
    db->backend.wal_append = probe->append;
    blob_gc_probe = NULL;
}

static int blob_crash_before_wal(void* ctx, const uint8_t* batch, size_t size)
{
    (void)ctx;
    (void)batch;
    (void)size;
    _exit(0);
}

static int blob_crash_after_wal(void* ctx, const tidesdb_wal_entry_t* entries, int count)
{
    (void)ctx;
    (void)entries;
    (void)count;
    _exit(0);
}

static tidesdb_config_t blob_config(char* dir, tidesdb_sync_mode_t sync_mode)
{
    tidesdb_config_t cfg = tidesdb_default_config();
    cfg.db_path = dir;
    cfg.memtable_write_buffer_size = BLOB_MEMTABLE_BYTES;
    cfg.memtable_sync_mode = sync_mode;
    cfg.num_flush_threads = 1;
    cfg.num_compaction_threads = 1;
    return cfg;
}

static tidesdb_t* blob_open(char* dir, tidesdb_sync_mode_t sync_mode, uint64_t max_blob_size)
{
    tidesdb_config_t cfg = blob_config(dir, sync_mode);
    tidesdb_open_options_t options = {
        .size = sizeof(options),
        .max_blob_size = max_blob_size,
    };
    tidesdb_t* db = NULL;
    ASSERT_EQ(tidesdb_open_with_options(&cfg, &options, &db), TDB_SUCCESS);
    ASSERT_TRUE(db != NULL);
    return db;
}

static tidesdb_column_family_t* blob_create_cf(tidesdb_t* db)
{
    ASSERT_EQ(tidesdb_create_blob_column_family(db, BLOB_CF), TDB_SUCCESS);
    tidesdb_column_family_t* cf = tidesdb_get_column_family(db, BLOB_CF);
    ASSERT_TRUE(cf != NULL);
    return cf;
}

static void blob_expect_value(tidesdb_t* db, tidesdb_column_family_t* cf, const uint8_t* key,
                              size_t key_size, const uint8_t* want, size_t want_size)
{
    tidesdb_txn_t* txn = NULL;
    uint8_t* got = NULL;
    size_t got_size = 0;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_get(txn, cf, key, key_size, &got, &got_size), TDB_SUCCESS);
    ASSERT_EQ(got_size, want_size);
    if (want_size != 0) ASSERT_TRUE(memcmp(got, want, want_size) == 0);
    free(got);
    ASSERT_EQ(tidesdb_txn_rollback(txn), TDB_SUCCESS);
    tidesdb_txn_free(txn);
}

static void blob_expect_absent(tidesdb_t* db, tidesdb_column_family_t* cf, const uint8_t* key,
                               size_t key_size)
{
    tidesdb_txn_t* txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_contains(txn, cf, key, key_size), TDB_ERR_NOT_FOUND);
    ASSERT_EQ(tidesdb_txn_rollback(txn), TDB_SUCCESS);
    tidesdb_txn_free(txn);
}

static void blob_expect_range(tidesdb_txn_t* txn, tidesdb_column_family_t* cf, const uint8_t* key,
                              size_t key_size, size_t offset, size_t length, const uint8_t* want)
{
    uint8_t* got = NULL;
    size_t got_size = 0;
    ASSERT_EQ(tidesdb_txn_get_range(txn, cf, key, key_size, offset, length, &got, &got_size),
              TDB_SUCCESS);
    ASSERT_EQ(got_size, length);
    if (length == 0)
        ASSERT_TRUE(got == NULL);
    else
        ASSERT_TRUE(memcmp(got, want, length) == 0);
    free(got);
}

static void blob_expect_full_and_range(tidesdb_t* db, tidesdb_column_family_t* cf,
                                       const uint8_t* key, size_t key_size, const uint8_t* value,
                                       size_t value_size)
{
    tidesdb_txn_t* txn = NULL;
    uint8_t* full = NULL;
    size_t full_size = 0;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_get(txn, cf, key, key_size, &full, &full_size), TDB_SUCCESS);
    ASSERT_EQ(full_size, value_size);
    ASSERT_TRUE(memcmp(full, value, value_size) == 0);
    blob_expect_range(txn, cf, key, key_size, BLOB_RANGE_OFFSET, BLOB_RANGE_LENGTH,
                      full + BLOB_RANGE_OFFSET);
    blob_expect_range(txn, cf, key, key_size, full_size, 0, NULL);
    free(full);
    uint8_t* invalid = NULL;
    size_t invalid_size = 0;
    ASSERT_EQ(
        tidesdb_txn_get_range(txn, cf, key, key_size, value_size + 1, 0, &invalid, &invalid_size),
        TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_txn_get_range(txn, cf, key, key_size, value_size, 1, &invalid, &invalid_size),
              TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_txn_get_range(txn, cf, key, key_size, SIZE_MAX, 1, &invalid, &invalid_size),
              TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_txn_rollback(txn), TDB_SUCCESS);
    tidesdb_txn_free(txn);
}

static void blob_delete(tidesdb_t* db, tidesdb_column_family_t* cf, const uint8_t* key,
                        size_t key_size)
{
    tidesdb_txn_t* txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_delete(txn, cf, key, key_size), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
    tidesdb_txn_free(txn);
}

static void blob_put_kv(tidesdb_t* db, tidesdb_column_family_t* cf, const uint8_t* key,
                        size_t key_size, const uint8_t* value, size_t value_size)
{
    tidesdb_txn_t* txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(txn, cf, key, key_size, value, value_size, -1), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
    tidesdb_txn_free(txn);
}

static void blob_sidecar_path(const char* dir, uint64_t number, char* out, size_t out_size)
{
    char name[VLOG_SIDECAR_NAME_MAX];
    ASSERT_EQ(vlog_sidecar_name(number, 0, name, sizeof(name)), VLOG_OK);
    ASSERT_TRUE(snprintf(out, out_size, "%s%s%s", dir, PATH_SEPARATOR, name) > 0);
}

static void blob_copy_file(const char* source, const char* destination)
{
    FILE* in = fopen(source, "rb");
    ASSERT_TRUE(in != NULL);
    FILE* out = fopen(destination, "wb");
    ASSERT_TRUE(out != NULL);
    uint8_t bytes[1024];
    size_t count = 0;
    while ((count = fread(bytes, 1, sizeof(bytes), in)) != 0)
        ASSERT_EQ(fwrite(bytes, 1, count, out), count);
    ASSERT_TRUE(feof(in));
    ASSERT_EQ(fclose(out), 0);
    ASSERT_EQ(fclose(in), 0);
}

static void blob_corrupt_value_byte(tidesdb_t* db, vlog_id_t id, size_t value_offset)
{
    vlog_t* vlog = db->vlog;
    pthread_rwlock_rdlock(&vlog->index_rw);
    const size_t bucket = vlog_index_locate(vlog, id, NULL);
    ASSERT_TRUE(bucket != SIZE_MAX);
    const vlog_index_entry_t entry = vlog->buckets[bucket];
    pthread_rwlock_unlock(&vlog->index_rw);
    ASSERT_TRUE(value_offset < entry.value_len);
    block_manager_t* bm =
        atomic_load_explicit(&vlog->segments[entry.segment].bm, memory_order_acquire);
    ASSERT_TRUE(bm != NULL);
    const uint64_t payload = entry.offset + BLOCK_MANAGER_BLOCK_HEADER_SIZE + VLOG_BLK_HDR_SIZE;
    ASSERT_TRUE(payload <= INT64_MAX - value_offset);
    uint8_t corrupt = 0;
    ASSERT_EQ(block_manager_read_at_offset(bm, payload + value_offset, sizeof(corrupt), &corrupt),
              0);
    corrupt ^= BLOB_CORRUPT_VALUE;
    ASSERT_EQ(
        block_manager_write_at(bm, (int64_t)(payload + value_offset), &corrupt, sizeof(corrupt)),
        0);
}

static int blob_log_contains(const char* path, const char* needle)
{
    FILE* file = fopen(path, "rb");
    if (file == NULL) return 0;
    ASSERT_EQ(fseek(file, 0, SEEK_END), 0);
    const long end = ftell(file);
    ASSERT_TRUE(end >= 0);
    ASSERT_EQ(fseek(file, 0, SEEK_SET), 0);
    char* contents = malloc((size_t)end + 1u);
    ASSERT_TRUE(contents != NULL);
    ASSERT_EQ(fread(contents, 1, (size_t)end, file), (size_t)end);
    contents[end] = '\0';
    const int found = strstr(contents, needle) != NULL;
    free(contents);
    ASSERT_EQ(fclose(file), 0);
    return found;
}

/* run one process to the exact commit seam that surrounds WAL publication. the child exits without
 * cleanup so recovery, rather than close, decides whether the object became visible */
static void blob_crash_child(const char* phase)
{
    const uint8_t key[] = "crash-key";
    const uint8_t value[] = {0x22, 0x00, 0xee, 0x44};
    char dir[] = BLOB_DB_DIR;
    tidesdb_t* db = blob_open(dir, TDB_SYNC_FULL, 0);
    if (tidesdb_create_blob_column_family(db, BLOB_CF) != TDB_SUCCESS) _exit(1);
    tidesdb_column_family_t* cf = tidesdb_get_column_family(db, BLOB_CF);
    if (cf == NULL) _exit(1);
    if (strcmp(phase, BLOB_PHASE_PRE_WAL) == 0)
        db->backend.wal_append = blob_crash_before_wal;
    else if (strcmp(phase, BLOB_PHASE_POST_WAL) == 0)
        db->backend.apply = blob_crash_after_wal;
    else
        _exit(1);
    (void)tidesdb_blob_put(db, cf, key, sizeof(key) - 1, value, sizeof(value));
    _exit(1);
}

/* a crash before publication leaves only an unreferenced append and no key; after the fully synced
 * WAL append but before L0/MVCC publication recovery replays exactly the committed reference */
void test_blob_put_crash_on_either_side_of_wal_publication(void)
{
    const uint8_t key[] = "crash-key";
    const uint8_t value[] = {0x22, 0x00, 0xee, 0x44};
    const char* const phases[] = {BLOB_PHASE_PRE_WAL, BLOB_PHASE_POST_WAL};
    char dir[] = BLOB_DB_DIR;

    for (size_t i = 0; i < sizeof(phases) / sizeof(phases[0]); i++)
    {
        int exit_code = -1;
        (void)remove_directory(dir);
        ASSERT_EQ(test_spawn_self(blob_exe, BLOB_CHILD_FLAG, phases[i], BLOB_CHILD_NTH, &exit_code),
                  0);
        ASSERT_EQ(exit_code, 0);
        tidesdb_t* db = blob_open(dir, TDB_SYNC_FULL, 0);
        tidesdb_column_family_t* cf = tidesdb_get_column_family(db, BLOB_CF);
        ASSERT_TRUE(cf != NULL);
        if (strcmp(phases[i], BLOB_PHASE_PRE_WAL) == 0)
            blob_expect_absent(db, cf, key, sizeof(key) - 1);
        else
            blob_expect_value(db, cf, key, sizeof(key) - 1, value, sizeof(value));
        ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    }
    (void)remove_directory(dir);
}

/* a media put is not a generic put with a different threshold: the dedicated family prevents an
 * ordinary family's live value from being mistaken for a permanent blob reference */
void test_blob_put_requires_a_blob_column_family(void)
{
    char dir[] = BLOB_DB_DIR;
    (void)remove_directory(dir);
    tidesdb_t* db = blob_open(dir, TDB_SYNC_FULL, 0);

    tidesdb_column_family_config_t config = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, BLOB_PLAIN_CF, &config), TDB_SUCCESS);
    tidesdb_column_family_t* plain = tidesdb_get_column_family(db, BLOB_PLAIN_CF);
    ASSERT_TRUE(plain != NULL);
    ASSERT_EQ(tidesdb_blob_put(db, plain, (const uint8_t*)"key", 3, (const uint8_t*)"value", 5),
              TDB_ERR_INVALID_ARGS);

    tidesdb_column_family_t* media = blob_create_cf(db);
    tidesdb_txn_t* txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(txn, media, (const uint8_t*)"key", 3, (const uint8_t*)"value", 5, -1),
              TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_txn_rollback(txn), TDB_SUCCESS);
    tidesdb_txn_free(txn);

    tidesdb_column_family_config_t blob_config = tidesdb_default_column_family_config();
    blob_config.keep_values_inline = 1;
    ASSERT_EQ(tidesdb_cf_update_runtime_config(db, media, &blob_config, 1), TDB_ERR_INVALID_ARGS);
    blob_config.keep_values_inline = 0;
    blob_config.encoding_count = 1;
    ASSERT_EQ(tidesdb_cf_update_runtime_config(db, media, &blob_config, 1), TDB_ERR_INVALID_ARGS);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(dir);
}

/* keys name immutable objects: exact retries are safe, while a second byte sequence cannot replace
 * the identity that the first successful call made live */
void test_blob_put_is_idempotent_and_conflicts_on_different_bytes(void)
{
    const uint8_t key[] = "photo";
    const uint8_t first[] = {0x00, 0x52, 0x80, 0xff};
    const uint8_t different[] = {0x00, 0x52, 0x81, 0xff};
    char dir[] = BLOB_DB_DIR;
    (void)remove_directory(dir);
    tidesdb_t* db = blob_open(dir, TDB_SYNC_FULL, 0);
    tidesdb_column_family_t* cf = blob_create_cf(db);
    ASSERT_EQ(tidesdb_create_blob_column_family(db, BLOB_CF), TDB_ERR_EXISTS);

    ASSERT_EQ(tidesdb_blob_put(db, cf, key, sizeof(key) - 1, first, sizeof(first)), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_blob_put(db, cf, key, sizeof(key) - 1, first, sizeof(first)), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_blob_put(db, cf, key, sizeof(key) - 1, different, sizeof(different)),
              TDB_ERR_CONFLICT);
    blob_expect_value(db, cf, key, sizeof(key) - 1, first, sizeof(first));

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(dir);
}

/* callers lend the bytes only through return, including the no-byte object form, so a successful
 * put must not retain the caller's buffer */
void test_blob_put_copies_before_return_and_accepts_an_empty_object(void)
{
    const uint8_t key[] = "copied";
    const uint8_t empty_key[] = "empty";
    uint8_t value[BLOB_VALUE_BYTES];
    uint8_t expected[BLOB_VALUE_BYTES];
    char dir[] = BLOB_DB_DIR;
    (void)remove_directory(dir);
    memset(value, 0xa5, sizeof(value));
    memcpy(expected, value, sizeof(expected));

    tidesdb_t* db = blob_open(dir, TDB_SYNC_FULL, 0);
    tidesdb_column_family_t* cf = blob_create_cf(db);
    ASSERT_EQ(tidesdb_blob_put(db, cf, key, sizeof(key) - 1, value, sizeof(value)), TDB_SUCCESS);
    memset(value, 0x5a, sizeof(value));
    ASSERT_EQ(tidesdb_blob_put(db, cf, empty_key, sizeof(empty_key) - 1, NULL, 0), TDB_SUCCESS);

    blob_expect_value(db, cf, key, sizeof(key) - 1, expected, sizeof(expected));
    blob_expect_value(db, cf, empty_key, sizeof(empty_key) - 1, NULL, 0);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(dir);
}

/* the configured ceiling is checked before append or publication: a refused object is neither a
 * visible key nor a leaked prefix that can change the result of a later retry */
void test_blob_put_enforces_the_configured_size_limit_before_side_effects(void)
{
    const uint8_t exact_key[] = "exact";
    const uint8_t over_key[] = "over";
    uint8_t exact[BLOB_LIMIT_BYTES];
    uint8_t over[BLOB_LIMIT_BYTES + 1];
    char dir[] = BLOB_DB_DIR;
    (void)remove_directory(dir);
    memset(exact, 0x3c, sizeof(exact));
    memset(over, 0xc3, sizeof(over));

    tidesdb_t* db = blob_open(dir, TDB_SYNC_FULL, BLOB_LIMIT_BYTES);
    tidesdb_column_family_t* cf = blob_create_cf(db);
    ASSERT_EQ(tidesdb_blob_put(db, cf, exact_key, sizeof(exact_key) - 1, exact, sizeof(exact)),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_blob_put(db, cf, over_key, sizeof(over_key) - 1, over, sizeof(over)),
              TDB_ERR_TOO_LARGE);
    blob_expect_value(db, cf, exact_key, sizeof(exact_key) - 1, exact, sizeof(exact));
    blob_expect_absent(db, cf, over_key, sizeof(over_key) - 1);

    vlog_stats_t before, after;
    ASSERT_EQ(vlog_get_stats(db->vlog, &before), VLOG_OK);
    ASSERT_EQ(tidesdb_blob_put(db, cf, over_key, SIZE_MAX, over, 1), TDB_ERR_TOO_LARGE);
    ASSERT_EQ(tidesdb_blob_put(db, cf, over_key, sizeof(over_key), over, SIZE_MAX),
              TDB_ERR_TOO_LARGE);
    ASSERT_EQ(vlog_get_stats(db->vlog, &after), VLOG_OK);
    ASSERT_EQ(before.bytes_written, after.bytes_written);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    db = blob_open(dir, TDB_SYNC_FULL, UINT64_MAX);
    cf = tidesdb_get_column_family(db, BLOB_CF);
    ASSERT_TRUE(cf != NULL);
    const size_t frame_max =
        (size_t)(tdb_single_io_limit() - block_manager_framed_size(VLOG_BLK_HDR_SIZE));
    ASSERT_EQ(db->max_blob_size, frame_max);
    ASSERT_EQ(vlog_get_stats(db->vlog, &before), VLOG_OK);
    ASSERT_EQ(tidesdb_blob_put(db, cf, over_key, sizeof(over_key), over, frame_max + 1),
              TDB_ERR_TOO_LARGE);
    ASSERT_EQ(vlog_get_stats(db->vlog, &after), VLOG_OK);
    ASSERT_EQ(before.bytes_written, after.bytes_written);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(dir);
}

/* the WAL must carry only the durable value-log reference, and the flush must preserve that very
 * id rather than materializing or respilling the media bytes */
void test_blob_put_wal_and_flush_preserve_the_value_log_reference(void)
{
    const uint8_t key[] = "reference";
    const uint8_t value[] = {0x91, 0x83, 0x01, 0xfe, 0x00};
    char dir[] = BLOB_DB_DIR;
    (void)remove_directory(dir);
    tidesdb_t* db = blob_open(dir, TDB_SYNC_FULL, 0);
    tidesdb_column_family_t* cf = blob_create_cf(db);
    blob_wal_probe_t probe;
    memset(&probe, 0, sizeof(probe));
    blob_install_wal_probe(db, &probe);
    ASSERT_EQ(tidesdb_blob_put(db, cf, key, sizeof(key) - 1, value, sizeof(value)), TDB_SUCCESS);
    blob_remove_wal_probe(db, &probe);
    ASSERT_EQ(probe.decoded, 0);
    ASSERT_TRUE((probe.entry.flags & TDB_WAL_ENTRY_VLOG_REF) != 0);
    ASSERT_TRUE(probe.entry.value == NULL);
    ASSERT_EQ(probe.entry.value_size, sizeof(value));
    ASSERT_TRUE(probe.entry.vlog_id != 0);

    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    cf_t* internal_cf = (cf_t*)cf;
    level_set_t* levels = atomic_load_explicit(&internal_cf->levels, memory_order_acquire);
    sstable_t* tables[1];
    ASSERT_EQ(level_set_overlapping(levels, LEVEL_SET_L1, key, sizeof(key) - 1, key,
                                    sizeof(key) - 1, tables, 1),
              1);
    uint8_t* stored = NULL;
    size_t stored_size = 0;
    uint64_t vlog_id = 0;
    uint64_t sequence = 0;
    int64_t ttl = 0;
    uint8_t deleted = 0;
    ASSERT_EQ(sstable_get(tables[0], key, sizeof(key) - 1, &stored, &stored_size, &vlog_id,
                          &sequence, &ttl, &deleted),
              TDB_SUCCESS);
    ASSERT_TRUE(stored == NULL);
    ASSERT_EQ(stored_size, sizeof(value));
    ASSERT_EQ(vlog_id, probe.entry.vlog_id);
    ASSERT_EQ(deleted, 0);
    if (sstable_unref(tables[0])) sstable_close(tables[0]);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(dir);
}

/* the pre-apply builder token is the only guard left after an older memtable flushes. force the
 * newly appended blob segment to seal, then reclaim it inside the WAL seam; a successful read
 * proves reclaim could not unlink the reference before L0 took ownership */
static void blob_gc_before_l0_handoff(uint32_t max_groups)
{
    const uint8_t key[] = "gc-window";
    uint8_t value[BLOB_GC_VALUE_BYTES];
    char dir[] = BLOB_DB_DIR;
    (void)remove_directory(dir);
    memset(value, 0x9d, sizeof(value));
    tidesdb_config_t cfg = blob_config(dir, TDB_SYNC_FULL);
    cfg.vlog_segment_size = BLOB_GC_SEGMENT_BYTES;
    tidesdb_open_options_t options = {.size = sizeof(options), .max_blob_shard_groups = max_groups};
    tidesdb_t* db = NULL;
    ASSERT_EQ(tidesdb_open_with_options(&cfg, &options, &db), TDB_SUCCESS);
    tidesdb_column_family_config_t plain_config = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, BLOB_PLAIN_CF, &plain_config), TDB_SUCCESS);
    tidesdb_column_family_t* plain = tidesdb_get_column_family(db, BLOB_PLAIN_CF);
    ASSERT_TRUE(plain != NULL);
    tidesdb_txn_t* seed = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &seed), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(seed, plain, (const uint8_t*)"seed", 4, (const uint8_t*)"x", 1, -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(seed), TDB_SUCCESS);
    tidesdb_txn_free(seed);

    tidesdb_column_family_t* cf = blob_create_cf(db);
    blob_gc_probe_t probe;
    memset(&probe, 0, sizeof(probe));
    blob_install_gc_probe(db, &probe);
    const int rc =
        max_groups ? tidesdb_blob_put_group(db, cf, 0, key, sizeof(key) - 1, value, sizeof(value))
                   : tidesdb_blob_put(db, cf, key, sizeof(key) - 1, value, sizeof(value));
    ASSERT_EQ(rc, TDB_SUCCESS);
    blob_remove_gc_probe(db, &probe);
    ASSERT_EQ(probe.rc, VLOG_OK);
    ASSERT_TRUE(probe.after.reclaim_calls > probe.before.reclaim_calls);
    ASSERT_EQ(probe.after.segments_retired, probe.before.segments_retired);
    ASSERT_EQ(vlog_reclaim(db->vlog), VLOG_OK); /* the receiving memtable now owns the hold */
    blob_expect_value(db, cf, key, sizeof(key) - 1, value, sizeof(value));

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(dir);
}

void test_blob_put_builder_floor_survives_gc_before_l0_handoff(void)
{
    blob_gc_before_l0_handoff(0);
}

void test_grouped_blob_builder_and_memtable_handoff_protect_a_sealed_group(void)
{
    blob_gc_before_l0_handoff(1);
}

typedef struct
{
    tidesdb_t* db;
    tidesdb_column_family_t* cf;
    const uint8_t* key;
    size_t key_size;
    const uint8_t* value;
    size_t value_size;
    _Atomic(int)* ready;
    _Atomic(int)* start;
    int rc;
} blob_race_t;

static void* blob_put_racer(void* arg)
{
    blob_race_t* race = (blob_race_t*)arg;
    atomic_fetch_add_explicit(race->ready, 1, memory_order_release);
    for (int tick = 0; tick < BLOB_RACE_WAIT_TICKS; tick++)
    {
        if (atomic_load_explicit(race->start, memory_order_acquire) != 0) break;
        usleep(BLOB_RACE_WAIT_US);
    }
    if (atomic_load_explicit(race->start, memory_order_acquire) == 0)
    {
        race->rc = TDB_ERR_LOCKED;
        return NULL;
    }
    race->rc = tidesdb_blob_put(race->db, race->cf, race->key, race->key_size, race->value,
                                race->value_size);
    return NULL;
}

static int blob_run_race(tidesdb_t* db, tidesdb_column_family_t* cf, const uint8_t* key,
                         size_t key_size, const uint8_t* left, const uint8_t* right, int equal)
{
    _Atomic(int) ready = 0;
    _Atomic(int) start = 0;
    blob_race_t racers[2] = {
        {db, cf, key, key_size, left, 4, &ready, &start, TDB_ERR_IO},
        {db, cf, key, key_size, right, 4, &ready, &start, TDB_ERR_IO},
    };
    pthread_t threads[2];
    ASSERT_EQ(pthread_create(&threads[0], NULL, blob_put_racer, &racers[0]), 0);
    ASSERT_EQ(pthread_create(&threads[1], NULL, blob_put_racer, &racers[1]), 0);
    for (int tick = 0; tick < BLOB_RACE_WAIT_TICKS; tick++)
    {
        if (atomic_load_explicit(&ready, memory_order_acquire) == 2) break;
        usleep(BLOB_RACE_WAIT_US);
    }
    ASSERT_EQ(atomic_load_explicit(&ready, memory_order_acquire), 2);
    atomic_store_explicit(&start, 1, memory_order_release);
    ASSERT_EQ(pthread_join(threads[0], NULL), 0);
    ASSERT_EQ(pthread_join(threads[1], NULL), 0);
    if (equal)
    {
        ASSERT_EQ(racers[0].rc, TDB_SUCCESS);
        ASSERT_EQ(racers[1].rc, TDB_SUCCESS);
        return 0;
    }
    if (racers[0].rc == TDB_SUCCESS)
    {
        ASSERT_EQ(racers[1].rc, TDB_ERR_CONFLICT);
        return 0;
    }
    ASSERT_EQ(racers[0].rc, TDB_ERR_CONFLICT);
    ASSERT_EQ(racers[1].rc, TDB_SUCCESS);
    return 1;
}

/* concurrent creators must pass through the same identity rule as retries: same bytes both win,
 * different bytes leave exactly one published object and one conflict */
void test_blob_put_concurrent_creators_obey_identity(void)
{
    const uint8_t equal_key[] = "equal";
    const uint8_t unequal_key[] = "unequal";
    const uint8_t left[] = {1, 2, 3, 4};
    const uint8_t right[] = {1, 2, 3, 5};
    char dir[] = BLOB_DB_DIR;
    (void)remove_directory(dir);
    tidesdb_t* db = blob_open(dir, TDB_SYNC_FULL, 0);
    tidesdb_column_family_t* cf = blob_create_cf(db);

    ASSERT_EQ(blob_run_race(db, cf, equal_key, sizeof(equal_key) - 1, left, left, 1), 0);
    blob_expect_value(db, cf, equal_key, sizeof(equal_key) - 1, left, sizeof(left));
    const int winner = blob_run_race(db, cf, unequal_key, sizeof(unequal_key) - 1, left, right, 0);
    blob_expect_value(db, cf, unequal_key, sizeof(unequal_key) - 1, winner == 0 ? left : right,
                      sizeof(left));

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(dir);
}

/* a reference written to the WAL remains a reference through L0 and a flush, so all three sync
 * modes retain the original object across the durable operation appropriate to that mode */
void test_blob_put_survives_wal_sync_flush_and_reopen_for_each_sync_mode(void)
{
    const tidesdb_sync_mode_t modes[] = {TDB_SYNC_FULL, TDB_SYNC_INTERVAL, TDB_SYNC_NONE};
    const uint8_t key[] = "durable";
    const uint8_t value[] = {0x7f, 0x00, 0x10, 0xfe, 0x01};
    char dir[] = BLOB_DB_DIR;

    for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++)
    {
        (void)remove_directory(dir);
        tidesdb_t* db = blob_open(dir, modes[i], 0);
        tidesdb_column_family_t* cf = blob_create_cf(db);
        ASSERT_EQ(tidesdb_blob_put(db, cf, key, sizeof(key) - 1, value, sizeof(value)),
                  TDB_SUCCESS);
        ASSERT_EQ(tidesdb_sync_wal(db), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

        db = blob_open(dir, modes[i], 0);
        cf = tidesdb_get_column_family(db, BLOB_CF);
        ASSERT_TRUE(cf != NULL);
        blob_expect_value(db, cf, key, sizeof(key) - 1, value, sizeof(value));
        ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    }
    (void)remove_directory(dir);
}

/* first exercise the piece-5 size tag with nonzero bytes beyond its end. a shorter tag cannot
 * turn on placement. the explicit API must distinguish a missing group from a supplied zero. */
void test_blob_group_zero_requires_opt_in_and_an_explicit_id(void)
{
    char dir[] = BLOB_DB_DIR;
    (void)remove_directory(dir);
    tidesdb_config_t cfg = blob_config(dir, TDB_SYNC_FULL);
    tidesdb_open_options_t options = {
        .size = offsetof(tidesdb_open_options_t, max_blob_shard_groups),
        .max_blob_shard_groups = 1,
        .reserved = UINT32_MAX};
    tidesdb_t* db = NULL;
    const uint8_t key = 'k', value = 'v';
    ASSERT_EQ(tidesdb_open_with_options(&cfg, &options, &db), TDB_SUCCESS);
    tidesdb_column_family_t* media = blob_create_cf(db);
    ASSERT_EQ(tidesdb_blob_put_group(db, media, 0, &key, 1, &value, 1), TDB_ERR_INVALID_ARGS);
    vlog_stats_t stats;
    ASSERT_EQ(vlog_get_stats(db->vlog, &stats), VLOG_OK);
    ASSERT_EQ(stats.bytes_written, 0u);
    ASSERT_EQ(stats.segment_count, 1u);
    ASSERT_EQ(tidesdb_blob_put(db, media, &key, 1, &value, 1), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    options.size = sizeof(options);
    ASSERT_EQ(tidesdb_open_with_options(&cfg, &options, &db), TDB_SUCCESS);
    media = tidesdb_get_column_family(db, BLOB_CF);
    /* validate placement before the idempotent-key check, too */
    ASSERT_EQ(tidesdb_blob_put(db, media, &key, 1, &value, 1), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_blob_put_group(db, media, 1, &key, 1, &value, 1), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_blob_put_group(db, media, UINT32_MAX, &key, 1, &value, 1),
              TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_blob_put_group(db, media, 0, &key, 1, &value, 1), TDB_SUCCESS);
    ASSERT_EQ(vlog_get_stats(db->vlog, &stats), VLOG_OK);
    ASSERT_EQ(stats.bytes_written, 0u);
    const uint8_t fresh = 'g';
    ASSERT_EQ(tidesdb_blob_put_group(db, media, 0, &fresh, 1, NULL, 0), TDB_SUCCESS);
    blob_expect_value(db, media, &fresh, 1, NULL, 0);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(dir);
}

/* a crashed grouped-file publisher can leave either its unpublished temporary name or a torn final
 * header. preflight must ignore only the former, reject the latter before recovery opens anything,
 * and leave the bytes as forensic evidence rather than letting block-manager recovery rewrite it.
 */
void test_blob_group_preflight_is_read_only_for_torn_and_temporary_files(void)
{
    char dir[] = BLOB_DB_DIR;
    char guard[MAX_FILE_PATH_LENGTH], temporary[MAX_FILE_PATH_LENGTH], torn[MAX_FILE_PATH_LENGTH];
    (void)remove_directory(dir);
    tidesdb_config_t cfg = blob_config(dir, TDB_SYNC_FULL);
    tidesdb_open_options_t options = {.size = sizeof(options), .max_blob_shard_groups = 2};
    tidesdb_t* db = NULL;
    const uint8_t key = 'k', value = 'v';
    ASSERT_EQ(tidesdb_open_with_options(&cfg, &options, &db), TDB_SUCCESS);
    tidesdb_column_family_t* media = blob_create_cf(db);
    ASSERT_EQ(tidesdb_blob_put_group(db, media, 1, &key, 1, &value, 1), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    ASSERT_TRUE(
        snprintf(guard, sizeof(guard), "%s%s%s", dir, PATH_SEPARATOR, VLOG_GROUP_GUARD_NAME) > 0);
    ASSERT_TRUE(snprintf(temporary, sizeof(temporary), "%s%s%s.tmp", guard, PATH_SEPARATOR,
                         "000000000777.vlog") > 0);
    int open_flags = O_WRONLY | O_CREAT | O_TRUNC;
#ifdef _WIN32
    open_flags |= O_BINARY;
#endif
    const int temp_fd = open(temporary, open_flags, 0644);
    ASSERT_TRUE(temp_fd >= 0);
    ASSERT_EQ(write(temp_fd, "partial", sizeof("partial") - 1), (ssize_t)(sizeof("partial") - 1));
    ASSERT_EQ(close(temp_fd), 0);

    db = NULL;
    ASSERT_EQ(tidesdb_open_with_options(&cfg, &options, &db), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    ASSERT_TRUE(snprintf(torn, sizeof(torn), "%s%s%s", guard, PATH_SEPARATOR, "000000000778.vlog") >
                0);
    const int torn_fd = open(torn, open_flags, 0644);
    ASSERT_TRUE(torn_fd >= 0);
    uint8_t torn_header[BLOCK_MANAGER_HEADER_SIZE] = {0};
    encode_uint32_le_compat(torn_header, BLOCK_MANAGER_MAGIC);
    torn_header[BLOCK_MANAGER_MAGIC_SIZE] = BLOCK_MANAGER_VERSION;
    ASSERT_EQ(write(torn_fd, torn_header, sizeof(torn_header)), (ssize_t)sizeof(torn_header));
    ASSERT_EQ(ftruncate(torn_fd, BLOCK_MANAGER_HEADER_SIZE + 4096), 0);
    ASSERT_EQ(close(torn_fd), 0);
    struct STAT_STRUCT before, after;
    ASSERT_EQ(STAT_FUNC(torn, &before), 0);

    db = NULL;
    ASSERT_EQ(tidesdb_open_with_options(&cfg, &options, &db), TDB_ERR_CORRUPTION);
    ASSERT_TRUE(db == NULL);
    ASSERT_EQ(STAT_FUNC(torn, &after), 0);
    ASSERT_EQ(after.st_size, before.st_size);
    (void)remove_directory(dir);
}

static void blob_expect_owner(vlog_t* vlog, vlog_id_t id, uint32_t want)
{
    uint32_t group = ~want;
    ASSERT_EQ(vlog_group_owner_of(vlog, id, &group), VLOG_OK);
    ASSERT_EQ(group, want);
}

typedef struct
{
    uint64_t seq[BLOB_BACKUP_WRITERS][BLOB_BACKUP_WRITES];
} blob_backup_commits_t;

/* each key belongs to one writer. joining the writers publishes the complete source history. */
static int blob_backup_note_commit(const tidesdb_commit_op_t* ops, int count, uint64_t seq,
                                   void* ctx)
{
    blob_backup_commits_t* commits = ctx;
    ASSERT_EQ(count, 1);
    ASSERT_EQ(ops[0].key_size, 2u);
    const uint8_t* key = ops[0].key;
    ASSERT_TRUE(key[0] < BLOB_BACKUP_WRITERS && key[1] < BLOB_BACKUP_WRITES);
    commits->seq[key[0]][key[1]] = seq;
    return 0;
}

typedef struct
{
    tidesdb_t* db;
    tidesdb_column_family_t* media;
    tidesdb_column_family_t* kv;
    unsigned int index;
    _Atomic(int)* start;
    _Atomic(int)* done;
    _Atomic(unsigned int)* committed_kv;
} blob_backup_writer_t;

typedef struct
{
    tidesdb_t* db;
    _Atomic(int)* start;
    _Atomic(int)* done;
    _Atomic(unsigned int)* calls;
} blob_backup_gc_t;

static void* blob_backup_writer(void* arg)
{
    blob_backup_writer_t* writer = arg;
    uint8_t value[BLOB_BACKUP_VALUE_BYTES];
    for (int tick = 0; !atomic_load(writer->start) && tick < BLOB_RACE_WAIT_TICKS; tick++)
        usleep(BLOB_RACE_WAIT_US);
    ASSERT_TRUE(atomic_load(writer->start));
    const uint32_t group = writer->index % 2u;
    for (unsigned int i = 0; i < BLOB_BACKUP_WRITES; i++)
    {
        const uint8_t key[] = {(uint8_t)writer->index, (uint8_t)i};
        memset(value, (int)(group + i), sizeof(value));
        ASSERT_EQ(tidesdb_blob_put_group(writer->db, writer->media, group, key, sizeof(key), value,
                                         sizeof(value)),
                  TDB_SUCCESS);
        blob_put_kv(writer->db, writer->kv, key, sizeof(key), value, sizeof(value));
        atomic_fetch_add(writer->committed_kv, 1);
    }
    atomic_fetch_add(writer->done, 1);
    return NULL;
}

static void* blob_backup_gc(void* arg)
{
    blob_backup_gc_t* gc = arg;
    for (int tick = 0; tick < BLOB_RACE_WAIT_TICKS; tick++)
    {
        if (atomic_load_explicit(gc->start, memory_order_acquire)) break;
        usleep(BLOB_RACE_WAIT_US);
    }
    for (int tick = 0;
         tick < BLOB_RACE_WAIT_TICKS && atomic_load(gc->done) < (int)BLOB_BACKUP_WRITERS; ++tick)
    {
        /* production claims this flag before enqueueing the worker. use its same exclusion with
         * a small test store below the scheduler's minimum garbage threshold. */
        int expected = 0;
        if (atomic_compare_exchange_strong(&gc->db->vlog_gc_active, &expected, 1))
        {
            engine_vlog_gc(gc->db);
            atomic_fetch_add(gc->calls, 1);
            atomic_store(&gc->db->vlog_gc_active, 0);
        }
        usleep(BLOB_RACE_WAIT_US);
    }
    return NULL;
}

/* a finished public backup is a complete cut: concurrent grouped and ordinary writers may advance
 * after that cut, but no pre-existing key or value-log reference may be missing. sealed sidecars
 * are copied with the image, and a same-number, same-length grouped sidecar from another database
 * must be rejected instead of lending its ids to this one. */
void test_blob_backup_captures_a_complete_cut_during_grouped_writes_and_gc(void)
{
    enum
    {
        seed_count = 8
    };
    char dir[] = BLOB_DB_DIR, backup[] = BLOB_BACKUP_DIR, foreign[] = BLOB_FOREIGN_DIR;
    (void)remove_directory(dir);
    (void)remove_directory(backup);
    (void)remove_directory(foreign);
    tidesdb_config_t cfg = blob_config(dir, TDB_SYNC_FULL);
    cfg.value_separation_threshold = 1;
    cfg.vlog_segment_size = BLOB_BACKUP_SEGMENT_BYTES;
    tidesdb_open_options_t options = {
        .size = sizeof(options), .enable_vlog_indexes = 1, .max_blob_shard_groups = 2};
    tidesdb_t* db = NULL;
    ASSERT_EQ(tidesdb_open_with_options(&cfg, &options, &db), TDB_SUCCESS);
    tidesdb_column_family_t* media = blob_create_cf(db);
    tidesdb_column_family_config_t plain_config = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, BLOB_PLAIN_CF, &plain_config), TDB_SUCCESS);
    tidesdb_column_family_t* kv = tidesdb_get_column_family(db, BLOB_PLAIN_CF);
    ASSERT_TRUE(kv != NULL);

    for (unsigned int i = 0; i < seed_count; i++)
    {
        char blob_key[24], kv_key[24];
        uint8_t blob_value[BLOB_BACKUP_VALUE_BYTES], kv_value[BLOB_BACKUP_VALUE_BYTES];
        const int blob_n = snprintf(blob_key, sizeof(blob_key), "seed-blob-%u", i);
        const int kv_n = snprintf(kv_key, sizeof(kv_key), "seed-kv-%u", i);
        ASSERT_TRUE(blob_n > 0 && (size_t)blob_n < sizeof(blob_key));
        ASSERT_TRUE(kv_n > 0 && (size_t)kv_n < sizeof(kv_key));
        memset(blob_value, (int)(0x40u + i), sizeof(blob_value));
        memset(kv_value, (int)(0x60u + i), sizeof(kv_value));
        ASSERT_EQ(tidesdb_blob_put_group(db, media, 0, (const uint8_t*)blob_key, (size_t)blob_n,
                                         blob_value, sizeof(blob_value)),
                  TDB_SUCCESS);
        blob_put_kv(db, kv, (const uint8_t*)kv_key, (size_t)kv_n, kv_value, sizeof(kv_value));
    }
    char local_index[256];
    blob_sidecar_path(dir, 1, local_index, sizeof(local_index));
    ASSERT_EQ(access(local_index, F_OK), 0);

    _Atomic(int) start = 0, done = 0;
    _Atomic(unsigned int) gc_calls = 0;
    _Atomic(unsigned int) committed_kv = 0;
    blob_backup_commits_t media_history = {0}, kv_history = {0};
    ASSERT_EQ(tidesdb_cf_set_commit_hook(db, media, blob_backup_note_commit, &media_history),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_cf_set_commit_hook(db, kv, blob_backup_note_commit, &kv_history),
              TDB_SUCCESS);
    blob_backup_writer_t writers[BLOB_BACKUP_WRITERS];
    pthread_t writer_threads[BLOB_BACKUP_WRITERS], gc_thread;
    for (unsigned int i = 0; i < BLOB_BACKUP_WRITERS; i++)
    {
        writers[i] = (blob_backup_writer_t){db, media, kv, i, &start, &done, &committed_kv};
        ASSERT_EQ(pthread_create(&writer_threads[i], NULL, blob_backup_writer, &writers[i]), 0);
    }
    blob_backup_gc_t gc = {db, &start, &done, &gc_calls};
    ASSERT_EQ(pthread_create(&gc_thread, NULL, blob_backup_gc, &gc), 0);
    atomic_store_explicit(&start, 1, memory_order_release);
    for (int tick = 0; tick < BLOB_RACE_WAIT_TICKS; tick++)
    {
        if (atomic_load_explicit(&committed_kv, memory_order_acquire) >= BLOB_BACKUP_WRITERS) break;
        usleep(BLOB_RACE_WAIT_US);
    }
    ASSERT_TRUE(atomic_load_explicit(&committed_kv, memory_order_acquire) >= BLOB_BACKUP_WRITERS);
    ASSERT_EQ(tidesdb_backup(db, backup), TDB_SUCCESS);
    for (unsigned int i = 0; i < BLOB_BACKUP_WRITERS; i++)
    {
        ASSERT_EQ(pthread_join(writer_threads[i], NULL), 0);
    }
    ASSERT_EQ(pthread_join(gc_thread, NULL), 0);
    ASSERT_TRUE(atomic_load_explicit(&gc_calls, memory_order_relaxed) > 0);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    cfg.db_path = backup;
    db = NULL;
    ASSERT_EQ(tidesdb_open_with_options(&cfg, &options, &db), TDB_SUCCESS);
    media = tidesdb_get_column_family(db, BLOB_CF);
    kv = tidesdb_get_column_family(db, BLOB_PLAIN_CF);
    ASSERT_TRUE(media != NULL && kv != NULL);
    for (unsigned int i = 0; i < seed_count; i++)
    {
        char blob_key[24], kv_key[24];
        uint8_t blob_value[BLOB_BACKUP_VALUE_BYTES], kv_value[BLOB_BACKUP_VALUE_BYTES];
        const int blob_n = snprintf(blob_key, sizeof(blob_key), "seed-blob-%u", i);
        const int kv_n = snprintf(kv_key, sizeof(kv_key), "seed-kv-%u", i);
        memset(blob_value, (int)(0x40u + i), sizeof(blob_value));
        memset(kv_value, (int)(0x60u + i), sizeof(kv_value));
        blob_expect_value(db, media, (const uint8_t*)blob_key, (size_t)blob_n, blob_value,
                          sizeof(blob_value));
        blob_expect_value(db, kv, (const uint8_t*)kv_key, (size_t)kv_n, kv_value, sizeof(kv_value));
    }
    ASSERT_TRUE(db->vlog->recovery_index_hits > 0);
    ASSERT_EQ(db->vlog->recovery_payload_bytes, 0u);
    const uint64_t cut = tidesdb_mvcc_visible_seq(db->clock);
    for (unsigned int writer = 0; writer < BLOB_BACKUP_WRITERS; writer++)
        for (unsigned int i = 0; i < BLOB_BACKUP_WRITES; i++)
        {
            const uint8_t key[] = {(uint8_t)writer, (uint8_t)i};
            uint8_t value[BLOB_BACKUP_VALUE_BYTES];
            memset(value, (int)(writer % 2u + i), sizeof(value));
            const uint64_t media_seq = media_history.seq[writer][i];
            const uint64_t kv_seq = kv_history.seq[writer][i];
            ASSERT_TRUE(media_seq > 0 && kv_seq > media_seq);
            if (media_seq <= cut)
                blob_expect_value(db, media, key, sizeof(key), value, sizeof(value));
            else
                blob_expect_absent(db, media, key, sizeof(key));
            if (kv_seq <= cut)
                blob_expect_value(db, kv, key, sizeof(key), value, sizeof(value));
            else
                blob_expect_absent(db, kv, key, sizeof(key));
        }
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    /* a separate store repeats the initial grouped record shape, retaining ids, frame lengths, and
     * the segment number while changing the payload fingerprint. */
    cfg.db_path = foreign;
    db = NULL;
    ASSERT_EQ(tidesdb_open_with_options(&cfg, &options, &db), TDB_SUCCESS);
    media = blob_create_cf(db);
    for (unsigned int i = 0; i < seed_count; i++)
    {
        char key[24];
        uint8_t value[BLOB_BACKUP_VALUE_BYTES];
        const int n = snprintf(key, sizeof(key), "seed-blob-%u", i);
        memset(value, (int)(0x80u + i), sizeof(value));
        ASSERT_EQ(tidesdb_blob_put_group(db, media, 0, (const uint8_t*)key, (size_t)n, value,
                                         sizeof(value)),
                  TDB_SUCCESS);
    }
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    char foreign_index[256], backup_index[256];
    blob_sidecar_path(foreign, 1, foreign_index, sizeof(foreign_index));
    blob_sidecar_path(backup, 1, backup_index, sizeof(backup_index));
    struct STAT_STRUCT local_stat, foreign_stat;
    ASSERT_EQ(STAT_FUNC(backup_index, &local_stat), 0);
    ASSERT_EQ(STAT_FUNC(foreign_index, &foreign_stat), 0);
    ASSERT_EQ(local_stat.st_size, foreign_stat.st_size);
    blob_copy_file(foreign_index, backup_index);

    cfg.db_path = backup;
    db = NULL;
    ASSERT_EQ(tidesdb_open_with_options(&cfg, &options, &db), TDB_SUCCESS);
    ASSERT_TRUE(db->vlog->recovery_payload_bytes > 0);
    media = tidesdb_get_column_family(db, BLOB_CF);
    uint8_t first[BLOB_BACKUP_VALUE_BYTES];
    memset(first, 0x40, sizeof(first));
    blob_expect_value(db, media, (const uint8_t*)"seed-blob-0", sizeof("seed-blob-0") - 1, first,
                      sizeof(first));
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    ASSERT_EQ(remove(backup_index), 0);
    db = NULL;
    ASSERT_EQ(tidesdb_open_with_options(&cfg, &options, &db), TDB_SUCCESS);
    ASSERT_TRUE(db->vlog->recovery_payload_bytes > 0);
    media = tidesdb_get_column_family(db, BLOB_CF);
    blob_expect_value(db, media, (const uint8_t*)"seed-blob-0", sizeof("seed-blob-0") - 1, first,
                      sizeof(first));
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(dir);
    (void)remove_directory(backup);
    (void)remove_directory(foreign);
}

/* a near-maximum ceiling touches two distant groups. all three routes reach the same WAL and
 * backup owners. a backup has its own files and must recover placement from the data itself. */
void test_blob_sparse_groups_interleave_with_kv_and_restore(void)
{
    char dir[] = BLOB_DB_DIR, backup[] = BLOB_DB_DIR "_backup";
    (void)remove_directory(dir);
    (void)remove_directory(backup);
    tidesdb_config_t cfg = blob_config(dir, TDB_SYNC_FULL);
    cfg.value_separation_threshold = 1;
    tidesdb_open_options_t options = {
        .size = sizeof(options), .enable_vlog_indexes = 1, .max_blob_shard_groups = UINT32_MAX - 1};
    tidesdb_t* db = NULL;
    ASSERT_EQ(tidesdb_open_with_options(&cfg, &options, &db), TDB_SUCCESS);
    tidesdb_column_family_t* media = blob_create_cf(db);
    tidesdb_column_family_config_t config = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, BLOB_PLAIN_CF, &config), TDB_SUCCESS);
    tidesdb_column_family_t* kv = tidesdb_get_column_family(db, BLOB_PLAIN_CF);
    const uint8_t a = 'a', b = 'b', k = 'k';
    const uint32_t high = options.max_blob_shard_groups - 1;
    vlog_stats_t stats;
    ASSERT_EQ(vlog_get_stats(db->vlog, &stats), VLOG_OK);
    ASSERT_EQ(stats.segment_count, 1u);
    blob_wal_probe_t probe = {0};
    blob_install_wal_probe(db, &probe);
    ASSERT_EQ(tidesdb_blob_put_group(db, media, 0, &a, 1, &a, 1), TDB_SUCCESS);
    const vlog_id_t id_a = probe.entry.vlog_id;
    tidesdb_txn_t* txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(txn, kv, &k, 1, &k, 1, -1), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
    tidesdb_txn_free(txn);
    const vlog_id_t id_k = probe.entry.vlog_id;
    ASSERT_EQ(tidesdb_blob_put_group(db, media, high, &b, 1, &b, 1), TDB_SUCCESS);
    const vlog_id_t id_b = probe.entry.vlog_id;
    blob_remove_wal_probe(db, &probe);
    ASSERT_EQ(tidesdb_blob_put_group(db, media, high, &a, 1, &a, 1), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_blob_put_group(db, media, high, &a, 1, &b, 1), TDB_ERR_CONFLICT);
    blob_expect_owner(db->vlog, id_a, 0);
    blob_expect_owner(db->vlog, id_b, high);
    blob_expect_owner(db->vlog, id_k, VLOG_GROUP_UNGROUPED);
    ASSERT_EQ(vlog_get_stats(db->vlog, &stats), VLOG_OK);
    ASSERT_EQ(stats.segment_count, 3u);
    ASSERT_EQ(stats.value_count, 3u);
    ASSERT_EQ(fd_manager_open_count(&db->fdm, FD_LABEL_VLOG_SEGMENT), 3);
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_backup(db, backup), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);

    cfg.db_path = backup;
    cfg.log_to_file = 1;
    options.max_blob_shard_groups = high;
    ASSERT_TRUE(access(BLOB_DB_DIR "_backup" PATH_SEPARATOR "LOCK", F_OK) != 0);
    db = NULL;
    ASSERT_EQ(tidesdb_open_with_options(&cfg, &options, &db), TDB_ERR_INVALID_ARGS);
    ASSERT_TRUE(db == NULL);
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_ERR_INVALID_ARGS);
    ASSERT_TRUE(db == NULL);
    ASSERT_TRUE(access(BLOB_DB_DIR "_backup" PATH_SEPARATOR "LOG", F_OK) != 0);
    ASSERT_TRUE(access(BLOB_DB_DIR "_backup" PATH_SEPARATOR "LOCK", F_OK) != 0);
    cfg.log_to_file = 0;
    options.max_blob_shard_groups = UINT32_MAX;
    ASSERT_EQ(tidesdb_open_with_options(&cfg, &options, &db), TDB_SUCCESS);
    media = tidesdb_get_column_family(db, BLOB_CF);
    kv = tidesdb_get_column_family(db, BLOB_PLAIN_CF);
    blob_expect_owner(db->vlog, id_a, 0);
    blob_expect_owner(db->vlog, id_b, high);
    blob_expect_owner(db->vlog, id_k, VLOG_GROUP_UNGROUPED);
    blob_expect_value(db, media, &a, 1, &a, 1);
    blob_expect_value(db, media, &b, 1, &b, 1);
    blob_expect_value(db, kv, &k, 1, &k, 1);
    ASSERT_EQ(tidesdb_blob_put_group(db, media, UINT32_MAX, &k, 1, &k, 1), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_blob_put_group(db, media, UINT32_MAX - 1, &k, 1, &k, 1), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(dir);
    (void)remove_directory(backup);
}

/* range reads resolve the same visible reference as a full media read, both from L0 and after the
 * reference has moved into an sstable. a valid endpoint at EOF names an empty object range. */
void test_blob_range_matches_full_read_before_and_after_flush(void)
{
    const uint8_t key[] = "range";
    const uint8_t empty_key[] = "empty-range";
    uint8_t value[BLOB_RANGE_VALUE_BYTES];
    char dir[] = BLOB_DB_DIR;
    (void)remove_directory(dir);
    for (size_t i = 0; i < sizeof(value); i++) value[i] = (uint8_t)i;

    tidesdb_t* db = blob_open(dir, TDB_SYNC_FULL, 0);
    tidesdb_column_family_t* cf = blob_create_cf(db);
    ASSERT_EQ(tidesdb_blob_put(db, cf, key, sizeof(key) - 1, value, sizeof(value)), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_blob_put(db, cf, empty_key, sizeof(empty_key) - 1, NULL, 0), TDB_SUCCESS);
    blob_expect_full_and_range(db, cf, key, sizeof(key) - 1, value, sizeof(value));
    tidesdb_txn_t* empty = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &empty), TDB_SUCCESS);
    blob_expect_range(empty, cf, empty_key, sizeof(empty_key) - 1, 0, 0, NULL);
    uint8_t* invalid = NULL;
    size_t invalid_size = 0;
    ASSERT_EQ(tidesdb_txn_get_range(empty, cf, empty_key, sizeof(empty_key) - 1, 1, 0, &invalid,
                                    &invalid_size),
              TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tidesdb_txn_rollback(empty), TDB_SUCCESS);
    tidesdb_txn_free(empty);
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    blob_expect_full_and_range(db, cf, key, sizeof(key) - 1, value, sizeof(value));
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(dir);
}

/* grouped media follows the same resolved-reference read path; the group owns placement, not the
 * value's range or visibility semantics. */
void test_grouped_blob_range_matches_full_read(void)
{
    const uint8_t key[] = "group-range";
    uint8_t value[BLOB_RANGE_VALUE_BYTES];
    char dir[] = BLOB_DB_DIR;
    (void)remove_directory(dir);
    for (size_t i = 0; i < sizeof(value); i++) value[i] = (uint8_t)(BLOB_RANGE_VALUE_BYTES - i);

    tidesdb_config_t cfg = blob_config(dir, TDB_SYNC_FULL);
    tidesdb_open_options_t options = {.size = sizeof(options), .max_blob_shard_groups = 2};
    tidesdb_t* db = NULL;
    ASSERT_EQ(tidesdb_open_with_options(&cfg, &options, &db), TDB_SUCCESS);
    tidesdb_column_family_t* cf = blob_create_cf(db);
    ASSERT_EQ(tidesdb_blob_put_group(db, cf, 1, key, sizeof(key) - 1, value, sizeof(value)),
              TDB_SUCCESS);
    blob_expect_full_and_range(db, cf, key, sizeof(key) - 1, value, sizeof(value));
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    blob_expect_full_and_range(db, cf, key, sizeof(key) - 1, value, sizeof(value));
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(dir);
}

/* verifying the whole framed block prevents a short read from accepting a damaged suffix, while
 * metadata-only operations remain usable without touching the corrupted payload. */
void test_blob_range_rejects_corruption_outside_the_requested_slice(void)
{
    const uint8_t key[] = "corrupt-range";
    uint8_t value[BLOB_RANGE_VALUE_BYTES];
    char dir[] = BLOB_DB_DIR;
    (void)remove_directory(dir);
    memset(value, BLOB_RANGE_FILL, sizeof(value));

    tidesdb_t* db = blob_open(dir, TDB_SYNC_FULL, 0);
    tidesdb_column_family_t* cf = blob_create_cf(db);
    blob_wal_probe_t probe = {0};
    blob_install_wal_probe(db, &probe);
    ASSERT_EQ(tidesdb_blob_put(db, cf, key, sizeof(key) - 1, value, sizeof(value)), TDB_SUCCESS);
    blob_remove_wal_probe(db, &probe);
    ASSERT_EQ(probe.decoded, 0);
    blob_corrupt_value_byte(db, probe.entry.vlog_id, BLOB_CORRUPT_BYTE);

    tidesdb_txn_t* txn = NULL;
    uint8_t* got = NULL;
    size_t got_size = 0;
    time_t ttl = 0;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_contains(txn, cf, key, sizeof(key) - 1), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_get_ttl(txn, cf, key, sizeof(key) - 1, &ttl), TDB_SUCCESS);
    ASSERT_EQ(ttl, TDB_TTL_NONE);
    const uint8_t different = 0;
    ASSERT_EQ(tidesdb_blob_put(db, cf, key, sizeof(key) - 1, &different, sizeof(different)),
              TDB_ERR_CONFLICT);
    ASSERT_EQ(tidesdb_txn_get(txn, cf, key, sizeof(key) - 1, &got, &got_size), TDB_ERR_CORRUPTION);
    ASSERT_EQ(tidesdb_txn_get_range(txn, cf, key, sizeof(key) - 1, 0, 1, &got, &got_size),
              TDB_ERR_CORRUPTION);
    ASSERT_EQ(
        tidesdb_txn_get_range(txn, cf, key, sizeof(key) - 1, sizeof(value), 0, &got, &got_size),
        TDB_ERR_CORRUPTION);
    ASSERT_EQ(tidesdb_txn_rollback(txn), TDB_SUCCESS);
    tidesdb_txn_free(txn);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(dir);
}

/* the public flag starts a real ticker rather than merely changing the direct vlog API. a valid
 * sidecar survives this post-seal payload flip, so the log's segment and frame offset prove the
 * background verifier, not recovery, found the damaged second object. */
void test_blob_scrub_ticker_reports_the_damaged_indexed_frame(void)
{
    const uint8_t clean_key[] = "scrub-clean";
    const uint8_t damaged_key[] = "scrub-damaged";
    uint8_t clean[BLOB_RANGE_VALUE_BYTES];
    uint8_t damaged[BLOB_RANGE_VALUE_BYTES];
    char dir[] = BLOB_DB_DIR;
    char log_path[MAX_FILE_PATH_LENGTH];
    char expected[2 * MAX_FILE_PATH_LENGTH];
    (void)remove_directory(dir);
    memset(clean, BLOB_RANGE_FILL, sizeof(clean));
    memset(damaged, BLOB_GC_FILL, sizeof(damaged));

    tidesdb_config_t cfg = blob_config(dir, TDB_SYNC_FULL);
    cfg.log_to_file = 1;
    cfg.log_level = TDB_LOG_ERROR;
    tidesdb_open_options_t options = {.size = sizeof(options), .enable_vlog_indexes = 1};
    tidesdb_t* db = NULL;
    ASSERT_EQ(tidesdb_open_with_options(&cfg, &options, &db), TDB_SUCCESS);
    tidesdb_column_family_t* cf = blob_create_cf(db);
    ASSERT_EQ(tidesdb_blob_put(db, cf, clean_key, sizeof(clean_key) - 1, clean, sizeof(clean)),
              TDB_SUCCESS);
    blob_wal_probe_t probe = {0};
    blob_install_wal_probe(db, &probe);
    ASSERT_EQ(
        tidesdb_blob_put(db, cf, damaged_key, sizeof(damaged_key) - 1, damaged, sizeof(damaged)),
        TDB_SUCCESS);
    blob_remove_wal_probe(db, &probe);
    ASSERT_EQ(probe.decoded, 0);
    const vlog_id_t damaged_id = probe.entry.vlog_id;
    pthread_rwlock_rdlock(&db->vlog->index_rw);
    const size_t bucket = vlog_index_locate(db->vlog, damaged_id, NULL);
    ASSERT_TRUE(bucket != SIZE_MAX);
    const vlog_index_entry_t entry = db->vlog->buckets[bucket];
    pthread_rwlock_unlock(&db->vlog->index_rw);
    const uint64_t segment = db->vlog->segments[entry.segment].number;
    ASSERT_EQ(vlog_segment_roll(db->vlog, entry.segment), VLOG_OK);
    blob_corrupt_value_byte(db, damaged_id, BLOB_CORRUPT_BYTE);
    ASSERT_TRUE(snprintf(log_path, sizeof(log_path), "%s%s%s", dir, PATH_SEPARATOR,
                         BLOB_SCRUB_LOG_NAME) > 0);
    ASSERT_TRUE(snprintf(expected, sizeof(expected),
                         "vlog scrub corruption in %s, segment %llu at offset %llu", dir,
                         (unsigned long long)segment, (unsigned long long)entry.offset) > 0);

    ASSERT_EQ(threadmanager_stop(db->threads, "vlog_scrub"), -1);
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    options.blob_scrub_enabled = 1;
    ASSERT_EQ(tidesdb_open_with_options(&cfg, &options, &db), TDB_SUCCESS);
#ifdef TDB_FAULT_INJECTION
    ASSERT_EQ(db->vlog->recovery_index_hits, 1);
    ASSERT_EQ(db->vlog->recovery_payload_bytes, 0);
#endif
    int reported = 0;
    for (size_t round = 0; round < BLOB_RACE_WAIT_TICKS; round++)
    {
        threadmanager_wake(db->threads, "vlog_scrub");
        usleep(BLOB_RACE_WAIT_US);
        if (blob_log_contains(log_path, expected))
        {
            reported = 1;
            break;
        }
    }
    ASSERT_TRUE(reported);
    uint8_t* got = NULL;
    size_t length = 0;
    ASSERT_EQ(vlog_read_range(db->vlog, damaged_id, 0, 1, &got, &length), VLOG_ERR_CORRUPTION);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(dir);
}

/* the range API is a visible-KV operation: inline values, a transaction's pending replacement,
 * and its pending tombstone must agree with get and contains before a media segment is involved. */
void test_range_read_obeys_inline_overlay_and_tombstone_visibility(void)
{
    const uint8_t key[] = "ordinary-range";
    const uint8_t inline_value[] = "abcdef";
    const uint8_t overlay_value[] = "uvwxyz";
    char dir[] = BLOB_DB_DIR;
    (void)remove_directory(dir);
    tidesdb_t* db = blob_open(dir, TDB_SYNC_FULL, 0);
    tidesdb_column_family_config_t config = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, BLOB_PLAIN_CF, &config), TDB_SUCCESS);
    tidesdb_column_family_t* cf = tidesdb_get_column_family(db, BLOB_PLAIN_CF);
    ASSERT_TRUE(cf != NULL);

    tidesdb_txn_t* txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    ASSERT_EQ(
        tidesdb_txn_put(txn, cf, key, sizeof(key) - 1, inline_value, sizeof(inline_value) - 1, -1),
        TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
    tidesdb_txn_free(txn);

    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    blob_expect_range(txn, cf, key, sizeof(key) - 1, BLOB_KV_SLICE_OFFSET, BLOB_KV_SLICE_LENGTH,
                      inline_value + BLOB_KV_SLICE_OFFSET);
    ASSERT_EQ(tidesdb_txn_put(txn, cf, key, sizeof(key) - 1, overlay_value,
                              sizeof(overlay_value) - 1, -1),
              TDB_SUCCESS);
    blob_expect_range(txn, cf, key, sizeof(key) - 1, BLOB_KV_SLICE_OFFSET, BLOB_KV_SLICE_LENGTH,
                      overlay_value + BLOB_KV_SLICE_OFFSET);
    ASSERT_EQ(tidesdb_txn_delete(txn, cf, key, sizeof(key) - 1), TDB_SUCCESS);
    uint8_t* missing = NULL;
    size_t missing_size = 0;
    ASSERT_EQ(tidesdb_txn_get_range(txn, cf, key, sizeof(key) - 1, 0, 1, &missing, &missing_size),
              TDB_ERR_NOT_FOUND);
    ASSERT_EQ(tidesdb_txn_rollback(txn), TDB_SUCCESS);
    tidesdb_txn_free(txn);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(dir);
}

/* deletes publish ordinary tombstones: a pre-delete snapshot keeps the blob readable, repeated
 * deletes stay idempotent, and releasing that snapshot permits the obsolete sealed segment to go.
 */
void test_blob_delete_snapshot_visibility_and_reclaim_after_release(void)
{
    const uint8_t key[] = "deleted-blob";
    const uint8_t roll_key[] = "roll";
    uint8_t value[BLOB_GC_VALUE_BYTES];
    const uint8_t roll_value = BLOB_ROLL_VALUE;
    char dir[] = BLOB_DB_DIR;
    (void)remove_directory(dir);
    memset(value, BLOB_GC_FILL, sizeof(value));

    tidesdb_config_t cfg = blob_config(dir, TDB_SYNC_FULL);
    cfg.vlog_segment_size = BLOB_GC_SEGMENT_BYTES;
    tidesdb_t* db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    tidesdb_column_family_t* cf = blob_create_cf(db);
    blob_wal_probe_t probe = {0};
    blob_install_wal_probe(db, &probe);
    ASSERT_EQ(tidesdb_blob_put(db, cf, key, sizeof(key) - 1, value, sizeof(value)), TDB_SUCCESS);
    blob_remove_wal_probe(db, &probe);
    ASSERT_EQ(probe.decoded, 0);
    uint64_t deleted_segment = 0;
    ASSERT_EQ(vlog_segment_of(db->vlog, probe.entry.vlog_id, &deleted_segment, NULL), VLOG_OK);
    char deleted_name[VLOG_SEGMENT_NAME_MAX];
    char deleted_path[MAX_FILE_PATH_LENGTH];
    ASSERT_EQ(vlog_segment_name(deleted_segment, deleted_name, sizeof(deleted_name)), VLOG_OK);
    ASSERT_TRUE(snprintf(deleted_path, sizeof(deleted_path), "%s%s%s", dir, PATH_SEPARATOR,
                         deleted_name) > 0);
    ASSERT_EQ(access(deleted_path, F_OK), 0);
    ASSERT_EQ(
        tidesdb_blob_put(db, cf, roll_key, sizeof(roll_key) - 1, &roll_value, sizeof(roll_value)),
        TDB_SUCCESS);
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);

    tidesdb_snapshot_t* snapshot = NULL;
    ASSERT_EQ(tidesdb_snapshot_create(db, &snapshot), TDB_SUCCESS);
    blob_delete(db, cf, key, sizeof(key) - 1);
    blob_delete(db, cf, key, sizeof(key) - 1);
    ASSERT_EQ(tidesdb_flush_memtable(db), TDB_SUCCESS);
    blob_expect_absent(db, cf, key, sizeof(key) - 1);

    tidesdb_txn_t* past = NULL;
    ASSERT_EQ(tidesdb_txn_begin_at_snapshot(db, snapshot, &past), TDB_SUCCESS);
    blob_expect_range(past, cf, key, sizeof(key) - 1, BLOB_RANGE_OFFSET, BLOB_RANGE_LENGTH,
                      value + BLOB_RANGE_OFFSET);
    ASSERT_EQ(tidesdb_txn_rollback(past), TDB_SUCCESS);
    tidesdb_txn_free(past);

    ASSERT_EQ(tidesdb_compact(db, cf), TDB_SUCCESS);
    vlog_stats_t held;
    engine_vlog_gc(db);
    ASSERT_EQ(vlog_get_stats(db->vlog, &held), VLOG_OK);
    uint64_t held_segment = 0;
    ASSERT_EQ(vlog_segment_of(db->vlog, probe.entry.vlog_id, &held_segment, NULL), VLOG_OK);
    ASSERT_EQ(held_segment, deleted_segment);
    ASSERT_EQ(access(deleted_path, F_OK), 0);
    ASSERT_EQ(tidesdb_txn_begin_at_snapshot(db, snapshot, &past), TDB_SUCCESS);
    blob_expect_range(past, cf, key, sizeof(key) - 1, BLOB_RANGE_OFFSET, BLOB_RANGE_LENGTH,
                      value + BLOB_RANGE_OFFSET);
    ASSERT_EQ(tidesdb_txn_rollback(past), TDB_SUCCESS);
    tidesdb_txn_free(past);

    tidesdb_snapshot_release(snapshot);
    ASSERT_EQ(tidesdb_compact(db, cf), TDB_SUCCESS);
    engine_vlog_gc(db);
    vlog_stats_t released;
    ASSERT_EQ(vlog_get_stats(db->vlog, &released), VLOG_OK);
    ASSERT_TRUE(released.segments_retired > held.segments_retired);
    ASSERT_EQ(access(deleted_path, F_OK), -1);
    ASSERT_EQ(errno, ENOENT);
    ASSERT_EQ(vlog_segment_of(db->vlog, probe.entry.vlog_id, &held_segment, NULL),
              VLOG_ERR_NOT_FOUND);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(dir);
}

int main(int argc, char** argv)
{
    if (argc == 4 && strcmp(argv[1], BLOB_CHILD_FLAG) == 0)
    {
        blob_crash_child(argv[2]);
        return 1;
    }
    blob_exe = argv[0];
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_blob_group_zero_requires_opt_in_and_an_explicit_id, tests_passed);
    RUN_TEST(test_blob_group_preflight_is_read_only_for_torn_and_temporary_files, tests_passed);
    RUN_TEST(test_blob_backup_captures_a_complete_cut_during_grouped_writes_and_gc, tests_passed);
    RUN_TEST(test_blob_sparse_groups_interleave_with_kv_and_restore, tests_passed);
    RUN_TEST(test_blob_put_requires_a_blob_column_family, tests_passed);
    RUN_TEST(test_blob_put_is_idempotent_and_conflicts_on_different_bytes, tests_passed);
    RUN_TEST(test_blob_put_copies_before_return_and_accepts_an_empty_object, tests_passed);
    RUN_TEST(test_blob_put_enforces_the_configured_size_limit_before_side_effects, tests_passed);
    RUN_TEST(test_blob_put_wal_and_flush_preserve_the_value_log_reference, tests_passed);
    RUN_TEST(test_blob_put_builder_floor_survives_gc_before_l0_handoff, tests_passed);
    RUN_TEST(test_grouped_blob_builder_and_memtable_handoff_protect_a_sealed_group, tests_passed);
    RUN_TEST(test_blob_put_crash_on_either_side_of_wal_publication, tests_passed);
    RUN_TEST(test_blob_put_concurrent_creators_obey_identity, tests_passed);
    RUN_TEST(test_blob_put_survives_wal_sync_flush_and_reopen_for_each_sync_mode, tests_passed);
    RUN_TEST(test_blob_range_matches_full_read_before_and_after_flush, tests_passed);
    RUN_TEST(test_grouped_blob_range_matches_full_read, tests_passed);
    RUN_TEST(test_blob_range_rejects_corruption_outside_the_requested_slice, tests_passed);
    RUN_TEST(test_blob_scrub_ticker_reports_the_damaged_indexed_frame, tests_passed);
    RUN_TEST(test_range_read_obeys_inline_overlay_and_tombstone_visibility, tests_passed);
    RUN_TEST(test_blob_delete_snapshot_visibility_and_reclaim_after_release, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
