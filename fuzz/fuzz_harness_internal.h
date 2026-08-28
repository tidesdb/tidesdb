/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_FUZZ_HARNESS_INTERNAL_H__
#define __TIDESDB_FUZZ_HARNESS_INTERNAL_H__

#include <stdio.h>
#include <stdlib.h>

#include "db.h"
#include "fuzz_model.h"

/* the state and helpers the harness driver shares with the iteration oracle. the driver decodes the
 * input into operations and keeps the model in step; the oracle reads the database back and proves
 * it still matches. they are split so neither file carries the other's bulk, and this header is the
 * only thing between them. */

/* bounds chosen so the small keyspace collides constantly (dense overwrites and version chains, the
 * interesting states) while a spilled value crosses the default value-log threshold */
#define FX_MAX_CFS       6
#define FX_NAME_LEN      16
#define FX_PATH_LEN      512
#define FX_KEY_ALPHABET  6
#define FX_MAX_KLEN      4
#define FX_MAX_VLEN      2048
#define FX_SPILL_VLEN    1500 /* above the 1024 default spill threshold */
#define FX_WRITE_BUFFER  8192 /* small, so the run rotates and flushes often */
#define FX_MAX_OPS       4096
#define FX_BUSY_RETRIES  64
#define FX_BUSY_STALL_US 1000
#define FX_VALUE_TABLE   16 /* one in this many generated values spills */
/* the lifetimes a generated put may carry. the engine fixes an absolute deadline at the put and
 * then evaluates expiry against a one-second wall clock, so a lifetime elapsing mid-run would leave
 * the model and the database on opposite sides of that boundary and the oracle would be the thing
 * that failed. both of these are unambiguous for a whole run, which is what keeps the ttl field
 * carried through the wal, a flush, a compaction and a reopen without making the comparison racy --
 * an expiry the engine loses or brings forward turns into a missing key the model still expects */
#define FX_TTL_LONG_SECONDS 86400 /* outlives any run, so the entry stays visible throughout */
#define FX_TTL_TABLE        3     /* one in this many generated puts carries the long lifetime */
#define FX_XID_LEN          16    /* the generated two-phase transaction id, distinct per prepare */
/* an interval bound is drawn from the key alphabet and kept shorter than a key, so a generated
 * interval lands inside the keyspace and covers a useful share of it rather than falling outside */
#define FX_MAX_BOUND_LEN    2
#define FX_OPEN_ABOVE_TABLE 4 /* one interval in this many runs to the end of the family */
/* the listing buffer a recovery pass reads in-doubt transactions into */
#define FX_MAX_PREPARED 8

/**
 * fx_state_t
 * the harness state threaded through every operation
 * @field db the database under test
 * @field model the reference model the database is compared against
 * @field txn the single open transaction, mirroring the model, or NULL
 * @field prepared the single prepared transaction awaiting phase two, or NULL
 * @field prepared_xid the two-phase transaction id the prepared handle carries
 * @field prepared_xid_size length of prepared_xid, 0 when none is outstanding
 * @field txn_iso the level the open transaction was begun at
 * @field prepared_iso the level the prepared transaction was begun at
 * @field prepared_recovered the prepared handle came back from a reopen rather than a prepare
 * @field cf_names the live column family names, refreshed from the database after every lifecycle
 *        operation
 * @field cf_count how many of cf_names are live
 * @field db_dir the scratch directory the run's database lives in
 * @field sync_mode FUZZ_SYNC_NONE or FUZZ_SYNC_FULL
 * @field value_tag makes each generated value distinct so a stale read is detectable
 * @field verbose whether the run traces each operation to stderr
 * @field handles_at_open the live sstable handle count when this run's database opened; a closed
 *        database owns none of its own, so every close has to bring the count back here
 * @field layouts_at_open the live level-layout count when this run's database opened, checked the
 *        same way -- a layout that outlives its level set holds sstable references forever
 * @field log_level the engine log severity a run opens its databases with
 * @field data the fuzzer input the operation stream decodes from
 * @field size length of data
 * @field pos how far the decoder has consumed data
 */
typedef struct
{
    tidesdb_t *db;
    fuzz_model_t *model;
    tidesdb_txn_t *txn;
    tidesdb_txn_t *prepared;
    uint8_t prepared_xid[FX_XID_LEN];
    size_t prepared_xid_size;
    tidesdb_isolation_level_t txn_iso;
    tidesdb_isolation_level_t prepared_iso;
    int prepared_recovered;
    char cf_names[FX_MAX_CFS][FX_NAME_LEN];
    int cf_count;
    char db_dir[FX_PATH_LEN];
    int sync_mode;
    uint64_t value_tag;
    int verbose;
    int64_t handles_at_open;
    int64_t layouts_at_open;
    int log_level;

    const uint8_t *data;
    size_t size;
    size_t pos;
} fx_state_t;

/* an oracle failure aborts so the fuzzer records the input; the message localizes the divergence */
#define FUZZ_CHECK(cond, ...)                      \
    do                                             \
    {                                              \
        if (!(cond))                               \
        {                                          \
            fprintf(stderr, "FUZZ ORACLE FAIL: "); \
            fprintf(stderr, __VA_ARGS__);          \
            fprintf(stderr, "\n");                 \
            fflush(stderr);                        \
            abort();                               \
        }                                          \
    } while (0)

/**
 * fx_byte / fx_gen_key
 * draw the next input byte, or a bounded key built from several of them; a decoder past the end of
 * the input reads zeroes so a short input still runs
 * @param s the fuzz state holding the input cursor
 * @param s the harness state
 * @param key receives up to FX_MAX_KLEN bytes
 * @return the byte, or the key length
 */
uint8_t fx_byte(fx_state_t *s);
size_t fx_gen_key(fx_state_t *s, uint8_t *key);

/**
 * fx_cf_handle
 * look a column family up by name, failing the oracle when the database has lost it
 * @param db the database to look in
 * @param name the family name
 * @return the handle, never NULL
 */
tidesdb_column_family_t *fx_cf_handle(tidesdb_t *db, const char *name);

/**
 * fx_commit_txn
 * commit the open transaction and fold it into the model, asserting that a refusal is one an
 * outstanding prepared batch's reservation can account for; a run with no open transaction is a
 * no-op
 * @param s the harness state
 */
void fx_commit_txn(fx_state_t *s);

/**
 * fx_verify_cf / fx_full_verify
 * prove the database still matches the model, over one column family or every live one. both settle
 * the open transaction first, so the committed view they read is the one the model holds
 * @param s the harness state
 * @param db the database to read, either the one under test or a backup copy of it
 * @param cf the column family name to verify
 */
void fx_verify_cf(fx_state_t *s, tidesdb_t *db, const char *cf);
void fx_full_verify(fx_state_t *s, tidesdb_t *db);

/**
 * fx_conflict_expectation
 * what the engine must and may do with a commit or a prepare of the open transaction, derived from
 * the level it runs at and what an in-doubt batch holds
 * @param s the harness state
 * @param required receives 1 when the engine has to refuse
 * @param allowed receives 1 when the engine is entitled to refuse
 */
void fx_conflict_expectation(const fx_state_t *s, int *required, int *allowed);

/**
 * fx_check_handles
 * assert a closed database left no sstable handle or level layout behind
 * @param s the harness state
 * @param where names the close being checked, for the failure message
 */
void fx_check_handles(fx_state_t *s, const char *where);

/**
 * fx_db_config
 * the database configuration every open in a run uses, so the one under test and a backup copy of
 * it are opened the same way
 * @param s the harness state
 * @param path the directory to open
 * @return the configuration
 */
tidesdb_config_t fx_db_config(fx_state_t *s, char *path);

/**
 * fx_op_prepare / fx_op_commit_prepared / fx_op_rollback_prepared / fx_settle_prepared
 * the two-phase protocol, which leaves a batch in doubt between the prepare and the decision.
 * settle decides an outstanding one, which a column-family lifecycle operation does first
 * @param s the harness state
 */
void fx_op_prepare(fx_state_t *s);
void fx_op_commit_prepared(fx_state_t *s);
void fx_op_rollback_prepared(fx_state_t *s);
void fx_settle_prepared(fx_state_t *s);

/**
 * fx_op_reopen / fx_op_backup
 * rebuild a database from what reached the disk, then prove the whole model survived it
 * @param s the harness state
 */
void fx_op_reopen(fx_state_t *s);
void fx_op_backup(fx_state_t *s);

/**
 * fx_op_history_record / fx_op_history_dump
 * keep the last operations in memory and print them only when something diverges. tracing every
 * operation to stderr as it runs perturbs the timing enough to hide a race from the very run that
 * is meant to catch it, so the history is written where it costs nothing and read where it matters
 * @param fmt printf-style description of the operation just dispatched
 */
void fx_op_history_record(const char *fmt, ...);
void fx_op_history_dump(void);

#endif /* __TIDESDB_FUZZ_HARNESS_INTERNAL_H__ */
