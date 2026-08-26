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
#include "../src/compat.h" /* pthreads and usleep via the platform shim */
#include "../src/io/block_manager_fault.h"
#include "test_utils.h" /* spawn-self and the stdio sync, plus _exit on either platform */

static int tests_passed = 0;
static int tests_failed = 0;

/* this reproduces the crash-fuzzer's recovery scenario deterministically: instead of a real SIGKILL
 * at a scheduling-dependent moment, a child arms a torn write at the nth block-manager write and
 * crashes the instant it lands, so sweeping n covers every crash point in the phase under test.
 *
 * the child is this same binary run again with the phase and the crash point as arguments, rather
 * than a fork. that is what lets the suite run everywhere -- windows has no fork -- and it is the
 * sturdier shape anyway, since a forked child of a threaded process carries only the forking thread
 * and these children all start threads of their own */

/* the argument that puts a run into child mode, and the phase names the child dispatches on */
#define CR_CHILD_FLAG    "--crash-child"
#define CR_PHASE_FLUSH   "flush"
#define CR_PHASE_WAL     "wal"
#define CR_PHASE_COMPACT "compact"

/* this binary's own path, kept from argv so a child can be started from it */
static const char *cr_exe = NULL;

#define CR_DIR             "." PATH_SEPARATOR "test_crash_recovery"
#define CR_CF              "cf0"
#define CR_KEYS            12
#define CR_VAL_LEN         200        /* over the spill threshold, so values reach the value log */
#define CR_SPILL_THRESHOLD 64         /* klog value threshold, values past it spill to the vlog */
#define CR_MEMTABLE        (4u << 20) /* large enough that the committed keys never auto-flush */
#define CR_SWEEP_MAX       64   /* torn-write points to sweep, past a flush's real write count */
#define CR_POLL_TICKS      5000 /* safety bound on the crash poll, one millisecond each */
/* torn-write points to sweep while the commits themselves are running. a commit costs one counted
 * write, so the tear lands inside the loop for the first CR_KEYS of these and the rest run clean --
 * headroom kept deliberately, so the sweep still reaches the loop if a commit ever costs more */
#define CR_WAL_SWEEP_MAX 24
/* where the child records the commits that returned, outside the database directory so a reopen
 * does not see it as a stray file and so wiping the database between rounds does not take it */
#define CR_PROGRESS "." PATH_SEPARATOR "test_crash_recovery_committed"
/* keys the compaction round writes, split across two flushes so the merge has two inputs. sized so
 * the merge issues enough writes to tear at each of its phases rather than only in the middle of
 * one -- at this count it costs ten, against six for a quarter of it */
#define CR_COMPACT_KEYS 96
/* torn-write points to sweep across a forced merge of those two sstables. the merge issues ten, so
 * this covers every one and leaves headroom that also exercises a merge completing cleanly */
#define CR_COMPACT_SWEEP_MAX 16

static tidesdb_config_t cr_config(char *dir)
{
    tidesdb_config_t cfg = tidesdb_default_config();
    cfg.db_path = dir;
    cfg.memtable_write_buffer_size = CR_MEMTABLE;
    cfg.memtable_sync_mode =
        TDB_SYNC_FULL; /* a committed put is durable in the WAL for the check */
    cfg.num_flush_threads = 1;
    cfg.num_compaction_threads = 1;
    cfg.value_separation_threshold = CR_SPILL_THRESHOLD;
    return cfg;
}

/* run one crash round -- start a child on the named phase at the given crash point and wait for it
 * to die, leaving whatever it managed to write behind for the caller to reopen */
static void cr_run_round(const char *phase, uint64_t nth)
{
    char nth_text[32];
    snprintf(nth_text, sizeof(nth_text), "%llu", (unsigned long long)nth);
    ASSERT_EQ(test_spawn_self(cr_exe, CR_CHILD_FLAG, phase, nth_text), 0);
}

static _Atomic(int) cr_flush_done = 0;

static void *cr_flush_thread(void *arg)
{
    (void)tidesdb_flush_memtable((tidesdb_t *)arg);
    atomic_store_explicit(&cr_flush_done, 1, memory_order_release);
    return NULL;
}

/* the child: commit CR_KEYS spillable keys, arm a torn write at the nth flush write, run the flush
 * on a thread, and crash the moment the tear lands (or the flush finishes cleanly for a large n) */
static void cr_child(char *dir, uint64_t nth)
{
    tidesdb_config_t cfg = cr_config(dir);
    tidesdb_t *db = NULL;
    if (tidesdb_open(&cfg, &db) != TDB_SUCCESS) _exit(1);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    if (tidesdb_create_column_family(db, CR_CF, &cc) != TDB_SUCCESS) _exit(1);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, CR_CF);

    uint8_t val[CR_VAL_LEN];
    memset(val, 'v', sizeof(val));
    for (int i = 0; i < CR_KEYS; i++)
    {
        char key[16];
        snprintf(key, sizeof(key), "k%03d", i);
        tidesdb_txn_t *t = NULL;
        if (tidesdb_txn_begin(db, &t) != TDB_SUCCESS) _exit(1);
        (void)tidesdb_txn_put(t, cf, (const uint8_t *)key, strlen(key), val, sizeof(val), -1);
        if (tidesdb_txn_commit(t) != TDB_SUCCESS) _exit(1);
        tidesdb_txn_free(t);
    }

    /* count and tear only the flush's writes, the commits above already landed durably */
    block_manager_fault_arm_torn(nth);
    pthread_t th;
    if (pthread_create(&th, NULL, cr_flush_thread, db) != 0) _exit(1);
    for (int i = 0; i < CR_POLL_TICKS; i++)
    {
        if (block_manager_fault_tripped() ||
            atomic_load_explicit(&cr_flush_done, memory_order_acquire))
            break;
        usleep(1000);
    }
    _exit(0); /* crash -- no clean close, the flush thread and every fd die with the process */
}

/* read back k000 upwards and require every one of count keys with the value the writer used. nth
 * only names the torn write in the message, so a failure says which crash point produced it */
static void cr_require_all(tidesdb_t *db, const uint8_t *val, int count, uint64_t nth)
{
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, CR_CF);
    ASSERT_TRUE(cf != NULL);
    for (int i = 0; i < count; i++)
    {
        char key[16];
        snprintf(key, sizeof(key), "k%03d", i);
        uint8_t *v = NULL;
        size_t vs = 0;
        tidesdb_txn_t *rt = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &rt), TDB_SUCCESS);
        const int rc = tidesdb_txn_get(rt, cf, (const uint8_t *)key, strlen(key), &v, &vs);
        if (rc != TDB_SUCCESS)
            fprintf(stderr, "key %s lost at torn write nth=%llu rc=%d\n", key,
                    (unsigned long long)nth, rc);
        ASSERT_EQ(rc, TDB_SUCCESS);
        ASSERT_TRUE(vs == CR_VAL_LEN && memcmp(v, val, vs) == 0);
        free(v);
        (void)tidesdb_txn_rollback(rt);
        tidesdb_txn_free(rt);
    }
}

/* every torn-write point in a flush must reopen cleanly, and every committed key survives -- the
 * committed data is durable in the WAL and re-flushed on recovery no matter where the flush tore */
void test_crash_recovery_torn_flush(void)
{
    uint8_t val[CR_VAL_LEN];
    memset(val, 'v', sizeof(val));

    for (uint64_t nth = 1; nth <= CR_SWEEP_MAX; nth++)
    {
        (void)remove_directory(CR_DIR);
        cr_run_round(CR_PHASE_FLUSH, nth);

        tidesdb_config_t cfg = cr_config(CR_DIR);
        tidesdb_t *db = NULL;
        const int rc = tidesdb_open(&cfg, &db);
        if (rc != TDB_SUCCESS)
            fprintf(stderr, "reopen failed at torn write nth=%llu rc=%d\n", (unsigned long long)nth,
                    rc);
        ASSERT_EQ(rc, TDB_SUCCESS);
        cr_require_all(db, val, CR_KEYS, nth);
        ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    }
    (void)remove_directory(CR_DIR);
}

/* what the child's commit loop needs, so the loop can run on its own thread and leave the main
 * thread free to crash the process the moment the tear lands
 * @field db the database being committed to
 * @field cf the family the keys go to
 * @field progress the record of commits that returned, already durable when the crash comes */
typedef struct
{
    tidesdb_t *db;
    tidesdb_column_family_t *cf;
    FILE *progress;
} cr_commit_args_t;

static _Atomic(int) cr_commits_done = 0;

/* commit the keys one at a time, recording each commit that returned. under sync full a commit
 * returns only once its record is durable, so a key named in the record is one recovery owes
 * back */
static void *cr_commit_thread(void *arg)
{
    cr_commit_args_t *a = (cr_commit_args_t *)arg;
    uint8_t val[CR_VAL_LEN];
    memset(val, 'v', sizeof(val));

    for (int i = 0; i < CR_KEYS; i++)
    {
        char key[16];
        snprintf(key, sizeof(key), "k%03d", i);
        tidesdb_txn_t *t = NULL;
        if (tidesdb_txn_begin(a->db, &t) != TDB_SUCCESS) break;
        const int put =
            tidesdb_txn_put(t, a->cf, (const uint8_t *)key, strlen(key), val, sizeof(val), -1);
        const int commit = put == TDB_SUCCESS ? tidesdb_txn_commit(t) : put;
        tidesdb_txn_free(t);
        if (commit != TDB_SUCCESS) break;

        /* on disk before the next commit starts, so the parent never demands a key whose commit
         * had not yet returned when the process died */
        fprintf(a->progress, "%d\n", i);
        test_fsync_file(a->progress);
    }
    atomic_store_explicit(&cr_commits_done, 1, memory_order_release);
    return NULL;
}

/* the child: arm the torn write before committing, so the write that tears is one the commit path
 * issues rather than one a flush issues */
static void cr_wal_child(char *dir, uint64_t nth)
{
    tidesdb_config_t cfg = cr_config(dir);
    tidesdb_t *db = NULL;
    if (tidesdb_open(&cfg, &db) != TDB_SUCCESS) _exit(1);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    if (tidesdb_create_column_family(db, CR_CF, &cc) != TDB_SUCCESS) _exit(1);

    FILE *progress = fopen(CR_PROGRESS, "w");
    if (!progress) _exit(1);
    cr_commit_args_t args = {db, tidesdb_get_column_family(db, CR_CF), progress};
    if (!args.cf) _exit(1);

    block_manager_fault_arm_torn(nth);
    pthread_t th;
    if (pthread_create(&th, NULL, cr_commit_thread, &args) != 0) _exit(1);
    for (int i = 0; i < CR_POLL_TICKS; i++)
    {
        if (block_manager_fault_tripped() ||
            atomic_load_explicit(&cr_commits_done, memory_order_acquire))
            break;
        usleep(1000);
    }
    _exit(0); /* crash -- no clean close, the committing thread and every fd die with the process */
}

/* read back every commit the child recorded. a recorded commit had already returned, so the family
 * it went to was durable too, which is why the family is only required once one is found */
static void cr_require_committed(tidesdb_t *db, const uint8_t *val)
{
    FILE *progress = fopen(CR_PROGRESS, "r");
    if (!progress) return; /* the tear landed before any commit returned */

    tidesdb_column_family_t *cf = NULL;
    int i = 0;
    while (fscanf(progress, "%d", &i) == 1)
    {
        if (!cf)
        {
            cf = tidesdb_get_column_family(db, CR_CF);
            ASSERT_TRUE(cf != NULL);
        }
        char key[16];
        snprintf(key, sizeof(key), "k%03d", i);
        uint8_t *v = NULL;
        size_t vs = 0;
        tidesdb_txn_t *rt = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &rt), TDB_SUCCESS);
        const int rc = tidesdb_txn_get(rt, cf, (const uint8_t *)key, strlen(key), &v, &vs);
        if (rc != TDB_SUCCESS)
            fprintf(stderr, "committed key %s lost after crash, rc=%d\n", key, rc);
        ASSERT_EQ(rc, TDB_SUCCESS);
        ASSERT_TRUE(vs == CR_VAL_LEN && memcmp(v, val, vs) == 0);
        free(v);
        (void)tidesdb_txn_rollback(rt);
        tidesdb_txn_free(rt);
    }
    (void)fclose(progress);
}

/* a tear in a write the commit path issues must still leave a database that opens, and must not
 * shorten the durable prefix -- every commit that returned before the crash is still owed back.
 * this is the crash fuzzer's oracle with the crash point chosen rather than raced for */
void test_crash_recovery_torn_wal_append(void)
{
    uint8_t val[CR_VAL_LEN];
    memset(val, 'v', sizeof(val));

    for (uint64_t nth = 1; nth <= CR_WAL_SWEEP_MAX; nth++)
    {
        (void)remove_directory(CR_DIR);
        (void)remove(CR_PROGRESS);
        cr_run_round(CR_PHASE_WAL, nth);

        tidesdb_config_t cfg = cr_config(CR_DIR);
        tidesdb_t *db = NULL;
        const int rc = tidesdb_open(&cfg, &db);
        if (rc != TDB_SUCCESS)
            fprintf(stderr, "reopen failed at torn commit write nth=%llu rc=%d\n",
                    (unsigned long long)nth, rc);
        ASSERT_EQ(rc, TDB_SUCCESS);
        cr_require_committed(db, val);
        ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    }
    (void)remove_directory(CR_DIR);
    (void)remove(CR_PROGRESS);
}

/* the handles a forced merge needs, since it runs on its own thread while the main one waits to
 * crash the process
 * @field db the database being merged
 * @field cf the family to merge */
typedef struct
{
    tidesdb_t *db;
    tidesdb_column_family_t *cf;
} cr_compact_args_t;

static _Atomic(int) cr_compact_done = 0;

static void *cr_compact_thread(void *arg)
{
    const cr_compact_args_t *a = (const cr_compact_args_t *)arg;
    (void)tidesdb_compact(a->db, a->cf);
    atomic_store_explicit(&cr_compact_done, 1, memory_order_release);
    return NULL;
}

/* the child: build two overlapping sstables, then tear a write the forced merge issues. every key
 * is already durable in an sstable before the arming, so the merge is only rearranging what is
 * there and a crash inside it may not cost a single one */
static void cr_compact_child(char *dir, uint64_t nth)
{
    tidesdb_config_t cfg = cr_config(dir);
    tidesdb_t *db = NULL;
    if (tidesdb_open(&cfg, &db) != TDB_SUCCESS) _exit(1);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    if (tidesdb_create_column_family(db, CR_CF, &cc) != TDB_SUCCESS) _exit(1);
    cr_compact_args_t args = {db, tidesdb_get_column_family(db, CR_CF)};
    if (!args.cf) _exit(1);

    uint8_t val[CR_VAL_LEN];
    memset(val, 'v', sizeof(val));
    /* one flush per half, taking alternate keys, so the two sstables cover the same key range and
     * the merge has to interleave them rather than move one across wholesale */
    for (int half = 0; half < 2; half++)
    {
        for (int i = half; i < CR_COMPACT_KEYS; i += 2)
        {
            char key[16];
            snprintf(key, sizeof(key), "k%03d", i);
            tidesdb_txn_t *t = NULL;
            if (tidesdb_txn_begin(db, &t) != TDB_SUCCESS) _exit(1);
            const int put = tidesdb_txn_put(t, args.cf, (const uint8_t *)key, strlen(key), val,
                                            sizeof(val), -1);
            const int commit = put == TDB_SUCCESS ? tidesdb_txn_commit(t) : put;
            tidesdb_txn_free(t);
            if (commit != TDB_SUCCESS) _exit(1);
        }
        if (tidesdb_flush_memtable(db) != TDB_SUCCESS) _exit(1);
    }

    block_manager_fault_arm_torn(nth);
    pthread_t th;
    if (pthread_create(&th, NULL, cr_compact_thread, &args) != 0) _exit(1);
    for (int i = 0; i < CR_POLL_TICKS; i++)
    {
        if (block_manager_fault_tripped() ||
            atomic_load_explicit(&cr_compact_done, memory_order_acquire))
            break;
        usleep(1000);
    }
    _exit(0); /* crash -- no clean close, the merging thread and every fd die with the process */
}

/* a tear in a write the merge issues must cost nothing at all. this is the failure a flush cannot
 * have: a flush only adds, and its input is still in the wal to be redone, whereas a merge removes
 * what it replaces, so an output committed or an input unlinked out of order destroys data that was
 * already durable on disk and that no replay can bring back */
void test_crash_recovery_torn_compaction(void)
{
    uint8_t val[CR_VAL_LEN];
    memset(val, 'v', sizeof(val));

    for (uint64_t nth = 1; nth <= CR_COMPACT_SWEEP_MAX; nth++)
    {
        (void)remove_directory(CR_DIR);
        cr_run_round(CR_PHASE_COMPACT, nth);

        tidesdb_config_t cfg = cr_config(CR_DIR);
        tidesdb_t *db = NULL;
        const int rc = tidesdb_open(&cfg, &db);
        if (rc != TDB_SUCCESS)
            fprintf(stderr, "reopen failed at torn merge write nth=%llu rc=%d\n",
                    (unsigned long long)nth, rc);
        ASSERT_EQ(rc, TDB_SUCCESS);
        cr_require_all(db, val, CR_COMPACT_KEYS, nth);
        ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    }
    (void)remove_directory(CR_DIR);
}

/* the child half of a round -- run the named phase at the given crash point and never return. an
 * unknown phase exits non-zero, so a mistyped name fails the round rather than passing quietly by
 * doing nothing at all */
static void cr_run_child(const char *phase, uint64_t nth)
{
    char dir[] = CR_DIR;
    if (strcmp(phase, CR_PHASE_FLUSH) == 0) cr_child(dir, nth);
    if (strcmp(phase, CR_PHASE_WAL) == 0) cr_wal_child(dir, nth);
    if (strcmp(phase, CR_PHASE_COMPACT) == 0) cr_compact_child(dir, nth);
    _exit(2);
}

int main(int argc, char **argv)
{
    cr_exe = argv[0];

    /* a child run does its phase and dies inside it, so nothing below this ever executes for one */
    if (argc >= 4 && strcmp(argv[1], CR_CHILD_FLAG) == 0)
    {
        cr_run_child(argv[2], strtoull(argv[3], NULL, 10));
        return 2; /* unreachable -- the child exits inside its phase */
    }

    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_crash_recovery_torn_flush, tests_passed);
    RUN_TEST(test_crash_recovery_torn_wal_append, tests_passed);
    RUN_TEST(test_crash_recovery_torn_compaction, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
