/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "fuzz_harness.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/column_family/level/level_set.h"
#include "../src/sstable/sstable.h" /* sstable_live_handles, for the leak check */
#include "base/errors.h"            /* TDB_ERR_BUSY is engine-internal, not in the public db.h */
#include "base/log.h" /* tidesdb_log_set_sink, to land an engine trace beside a divergence */
#include "compat.h"   /* remove_directory, usleep, PATH_SEPARATOR */
#include "db.h"
#include "engine/engine.h" /* engine_vlog_gc */
#include "fuzz_harness_internal.h"
#include "fuzz_model.h"

/* the isolation levels a data transaction is opened at, drawn per transaction from the input.
 *
 * the harness drives one data transaction at a time, so nothing commits while one is open and every
 * level resolves reads against the same committed state -- which is why the model needs no
 * per-level read logic. what the level does change is the commit-time conflict check, and the only
 * peer a commit can conflict with here is an in-doubt prepared transaction. snapshot and
 * serializable claim a write reservation, so a prepared batch at one of those levels holds its keys
 * and refuses a commit that touches them; the weaker levels neither claim nor check one */
static const tidesdb_isolation_level_t FX_ISO_TABLE[] = {
    TDB_ISOLATION_READ_UNCOMMITTED, TDB_ISOLATION_READ_COMMITTED, TDB_ISOLATION_REPEATABLE_READ,
    TDB_ISOLATION_SNAPSHOT, TDB_ISOLATION_SERIALIZABLE};
#define FX_ISO_TABLE_LEN ((int)(sizeof(FX_ISO_TABLE) / sizeof(FX_ISO_TABLE[0])))

/* the level at or above which a transaction claims and checks a write reservation */
#define FX_ISO_RESERVES TDB_ISOLATION_SNAPSHOT

/* the operation the decoder selects; the table below weights the stream toward data operations */
typedef enum
{
    FX_PUT,
    FX_GET,
    FX_DELETE,
    FX_DELETE_RANGE,
    FX_DELETE_PREFIX,
    FX_CONTAINS,
    FX_BEGIN,
    FX_COMMIT,
    FX_ROLLBACK,
    FX_SAVEPOINT,
    FX_ROLLBACK_TO,
    FX_RELEASE,
    FX_ITER,
    FX_FLUSH,
    FX_COMPACT,
    FX_COMPACT_RANGE,
    FX_CHECKPOINT,
    FX_SYNC_WAL,
    FX_VLOG_GC,
    FX_CF_CREATE,
    FX_CF_DROP,
    FX_CF_RENAME,
    FX_CF_CLONE,
    FX_REOPEN,
    FX_BACKUP,
    FX_PREPARE,
    FX_COMMIT_PREPARED,
    FX_ROLLBACK_PREPARED,
    FX_TXN_RESET,
    FX_CF_RECONFIG,
    FX_OP_COUNT /* the number of operations, which the name table below is checked against */
} fx_op_t;

/* the weighted selection table: common data operations appear many times, rare structural ones once
 */
static const fx_op_t FX_OP_TABLE[] = {
    FX_PUT,
    FX_PUT,
    FX_PUT,
    FX_PUT,
    FX_GET,
    FX_GET,
    FX_GET,
    FX_DELETE,
    FX_DELETE,
    FX_DELETE_RANGE,
    FX_DELETE_PREFIX,
    FX_CONTAINS,
    FX_BEGIN,
    FX_COMMIT,
    FX_COMMIT,
    FX_ROLLBACK,
    FX_SAVEPOINT,
    FX_ROLLBACK_TO,
    FX_RELEASE,
    FX_ITER,
    FX_ITER,
    FX_FLUSH,
    FX_COMPACT,
    FX_COMPACT_RANGE,
    FX_CHECKPOINT,
    FX_SYNC_WAL,
    FX_VLOG_GC,
    FX_CF_CREATE,
    FX_CF_DROP,
    FX_CF_RENAME,
    FX_CF_CLONE,
    FX_REOPEN,
    FX_BACKUP,
    FX_PREPARE,
    FX_PREPARE,
    FX_COMMIT_PREPARED,
    FX_ROLLBACK_PREPARED,
    FX_TXN_RESET,
    FX_CF_RECONFIG,
};
#define FX_OP_TABLE_LEN ((int)(sizeof(FX_OP_TABLE) / sizeof(FX_OP_TABLE[0])))

/* ===== input reader ===== */

uint8_t fx_byte(fx_state_t *s)
{
    return s->pos < s->size ? s->data[s->pos++] : 0;
}

static int fx_exhausted(const fx_state_t *s)
{
    return s->pos >= s->size;
}

/* ===== value and key generation ===== */

size_t fx_gen_key(fx_state_t *s, uint8_t *key)
{
    const size_t klen = (size_t)(fx_byte(s) % FX_MAX_KLEN) + 1;
    for (size_t i = 0; i < klen; i++) key[i] = (uint8_t)('a' + (fx_byte(s) % FX_KEY_ALPHABET));
    return klen;
}

static size_t fx_gen_value(fx_state_t *s, uint8_t *val)
{
    const uint8_t sel = fx_byte(s);
    /* the low end of the table is zero, so roughly one generated value in sixteen is empty --
     * a value the engine stores and must not confuse with an absent key */
    size_t vlen = (sel % FX_VALUE_TABLE == FX_VALUE_TABLE - 1) ? FX_SPILL_VLEN
                                                               : (size_t)(sel % FX_VALUE_TABLE);
    if (vlen > FX_MAX_VLEN) vlen = FX_MAX_VLEN;
    const uint64_t tag = s->value_tag++;
    for (size_t i = 0; i < vlen; i++) val[i] = (uint8_t)(tag + i);
    return vlen;
}

/* the cf this operation targets, chosen from the live set */
static const char *fx_pick_cf(fx_state_t *s)
{
    return s->cf_names[fx_byte(s) % s->cf_count];
}

tidesdb_column_family_t *fx_cf_handle(tidesdb_t *db, const char *name)
{
    tidesdb_column_family_t *h = tidesdb_get_column_family(db, name);
    FUZZ_CHECK(h != NULL, "cf handle missing: %s", name);
    return h;
}

/* ===== transaction lifecycle mirrored on both sides ===== */

static void fx_ensure_txn(fx_state_t *s)
{
    if (s->txn) return;
    const tidesdb_isolation_level_t iso = FX_ISO_TABLE[fx_byte(s) % FX_ISO_TABLE_LEN];
    FUZZ_CHECK(tidesdb_txn_begin_with_isolation(s->db, iso, &s->txn) == TDB_SUCCESS,
               "txn_begin at isolation %d failed", (int)iso);
    s->txn_iso = iso;
    fuzz_model_txn_begin(s->model);
    if (s->verbose) fprintf(stderr, "    begin isolation %d\n", (int)iso);
}

/* whether a commit of the open transaction must be refused, and whether it may be, derived from
 * what the engine actually runs at each level.
 *
 * read-uncommitted and read-committed run no commit-time conflict detection at all --
 * txn_write_phase gates it on isolation above read-committed -- so a refusal at those levels is
 * always a fault. every level above runs detection and may legitimately refuse, and the oracle
 * cannot predict when, because all three checks are one-sided. the write reservation is a hash with
 * a 16-bit fingerprint that also loses conservatively against any newer sequence, read-set
 * revalidation refuses on a version that merely moved, and the serializable dangerous-structure
 * rule is the conservative Cahill pivot. so a refusal is permitted, never predicted.
 *
 * one refusal is required rather than permitted: a live prepared batch holds a reservation on its
 * keys until phase two decides it, so a transaction that both reserves and writes one of those keys
 * has to lose. a batch adopted after a restart is below snapshot isolation and holds no
 * reservation, so it requires nothing */
void fx_conflict_expectation(const fx_state_t *s, int *required, int *allowed)
{
    const int reserves = s->txn_iso >= FX_ISO_RESERVES;
    const int held = s->prepared && !s->prepared_recovered && s->prepared_iso >= FX_ISO_RESERVES;
    *allowed = s->txn_iso > TDB_ISOLATION_READ_COMMITTED;
    *required = reserves && held && fuzz_model_txn_hits_prepared(s->model);
}

void fx_commit_txn(fx_state_t *s)
{
    if (!s->txn) return;
    int required = 0, allowed = 0;
    fx_conflict_expectation(s, &required, &allowed);
    const int rc = tidesdb_txn_commit(s->txn);

    if (rc == TDB_ERR_CONFLICT)
    {
        FUZZ_CHECK(allowed, "commit refused at isolation %d, which runs no conflict detection",
                   (int)s->txn_iso);
        /* the transaction aborted, so the model discards its buffer rather than applying it */
        tidesdb_txn_free(s->txn);
        s->txn = NULL;
        fuzz_model_txn_rollback(s->model);
        return;
    }

    FUZZ_CHECK(rc == TDB_SUCCESS, "commit rc %d at isolation %d", rc, (int)s->txn_iso);
    FUZZ_CHECK(!required,
               "commit at isolation %d overwrote a key a live prepared batch at isolation %d holds",
               (int)s->txn_iso, (int)s->prepared_iso);
    tidesdb_txn_free(s->txn);
    s->txn = NULL;
    fuzz_model_txn_commit(s->model);
    /* checking after every commit costs the run its speed and buys the exact operation a
     * divergence appeared at, rather than whichever scan happened to notice it later */
    if (getenv("TIDESDB_FUZZ_VERIFY_EACH"))
        for (int i = 0; i < s->cf_count; i++) fx_verify_cf(s, s->db, s->cf_names[i]);
}

static void fx_rollback_txn(fx_state_t *s)
{
    if (!s->txn) return;
    (void)tidesdb_txn_rollback(s->txn);
    tidesdb_txn_free(s->txn);
    s->txn = NULL;
    fuzz_model_txn_rollback(s->model);
}

/* reset the open transaction to a fresh one at a new level, discarding its buffered writes. the
 * engine frees the transaction core and begins another, so the model rolls back and begins again */
static void fx_op_txn_reset(fx_state_t *s)
{
    fx_ensure_txn(s);
    const tidesdb_isolation_level_t iso = FX_ISO_TABLE[fx_byte(s) % FX_ISO_TABLE_LEN];
    FUZZ_CHECK(tidesdb_txn_reset(s->txn, iso) == TDB_SUCCESS, "txn_reset to isolation %d",
               (int)iso);
    s->txn_iso = iso;
    fuzz_model_txn_rollback(s->model);
    fuzz_model_txn_begin(s->model);
    if (s->verbose) fprintf(stderr, "    reset to isolation %d\n", (int)iso);
}

/* ===== point operations (read-your-own-writes: compared against the buffer-overlay model) ===== */

static void fx_op_put(fx_state_t *s)
{
    fx_ensure_txn(s);
    const char *cf = fx_pick_cf(s);
    uint8_t key[FX_MAX_KLEN];
    const size_t klen = fx_gen_key(s, key);
    uint8_t val[FX_MAX_VLEN];
    const size_t vlen = fx_gen_value(s, val);
    const time_t ttl = (fx_byte(s) % FX_TTL_TABLE) == 0 ? FX_TTL_LONG_SECONDS : FUZZ_TTL_NONE;
    const int rc = tidesdb_txn_put(s->txn, fx_cf_handle(s->db, cf), key, klen, val, vlen, ttl);
    FUZZ_CHECK(rc == TDB_SUCCESS, "put rc %d", rc);
    FUZZ_CHECK(fuzz_model_put(s->model, cf, key, klen, val, vlen, ttl), "model put");
    if (s->verbose)
        fprintf(stderr, "    put cf %s key %.*s vlen %zu ttl %lld\n", cf, (int)klen,
                (const char *)key, vlen, (long long)ttl);
}

static int fx_get_retry(fx_state_t *s, const char *cf, const uint8_t *key, size_t klen,
                        uint8_t **val, size_t *vlen)
{
    tidesdb_column_family_t *h = fx_cf_handle(s->db, cf);
    int rc = TDB_ERR_BUSY;
    for (int t = 0; t < FX_BUSY_RETRIES && rc == TDB_ERR_BUSY; t++)
    {
        rc = tidesdb_txn_get(s->txn, h, key, klen, val, vlen);
        if (rc == TDB_ERR_BUSY) usleep(FX_BUSY_STALL_US);
    }
    return rc;
}

/* what a scan of the same key returns, at the moment a point get disagreed with the model. the two
 * read paths resolve differently -- a get walks the source stack and takes the first source holding
 * the key, a scan merges every source and takes the highest sequence -- so a scan that returns the
 * value the get did not is the source ordering having been broken rather than the version being
 * lost. the mirror of the point get fx_dump_divergence already runs when a scan is the one that
 * diverges */
static void fx_scan_says(fx_state_t *s, const char *cf, const uint8_t *key, size_t klen)
{
    tidesdb_txn_t *rt = NULL;
    if (tidesdb_txn_begin(s->db, &rt) != TDB_SUCCESS) return;
    tidesdb_iter_t *it = NULL;
    if (tidesdb_iter_new(rt, fx_cf_handle(s->db, cf), &it) == TDB_SUCCESS)
    {
        if (tidesdb_iter_seek(it, key, klen) == TDB_SUCCESS && tidesdb_iter_valid(it))
        {
            uint8_t *k = NULL, *v = NULL;
            size_t kl = 0, vl = 0;
            if (tidesdb_iter_key_value(it, &k, &kl, &v, &vl) == TDB_SUCCESS)
            {
                const int same = kl == klen && memcmp(k, key, kl) == 0;
                fprintf(stderr, "  scan  len %zu first %02x%s\n", same ? vl : (size_t)0,
                        same && vl ? v[0] : 0, same ? "" : " (scan landed on a different key)");
                free(k);
                free(v);
            }
        }
        else
            fprintf(stderr, "  scan  found no key at or past this one\n");
        tidesdb_iter_free(it);
    }
    (void)tidesdb_txn_rollback(rt);
    tidesdb_txn_free(rt);
}

static void fx_op_get(fx_state_t *s)
{
    fx_ensure_txn(s);
    const char *cf = fx_pick_cf(s);
    uint8_t key[FX_MAX_KLEN];
    const size_t klen = fx_gen_key(s, key);

    uint8_t *dbv = NULL;
    size_t dbvlen = 0;
    const int rc = fx_get_retry(s, cf, key, klen, &dbv, &dbvlen);

    const uint8_t *mv = NULL;
    size_t mvlen = 0;
    const int present = fuzz_model_get(s->model, cf, key, klen, &mv, &mvlen);

    if (rc == TDB_SUCCESS)
    {
        FUZZ_CHECK(present, "get: db found a key the model does not have");
        if (!fuzz_value_eq(dbv, dbvlen, mv, mvlen))
        {
            fprintf(stderr, "\nget mismatch cf %s key %.*s\n  db    len %zu first %02x\n", cf,
                    (int)klen, (const char *)key, dbvlen, dbvlen ? dbv[0] : 0);
            fprintf(stderr, "  model len %zu first %02x\n", mvlen, mvlen ? mv[0] : 0);
            fx_scan_says(s, cf, key, klen);
            fx_op_history_dump();
        }
        FUZZ_CHECK(fuzz_value_eq(dbv, dbvlen, mv, mvlen), "get: value mismatch");
        free(dbv);
    }
    else
    {
        FUZZ_CHECK(rc == TDB_ERR_NOT_FOUND, "get: unexpected rc %d", rc);
        FUZZ_CHECK(!present, "get: db missed a key the model has");
    }
}

static void fx_op_delete(fx_state_t *s)
{
    fx_ensure_txn(s);
    const char *cf = fx_pick_cf(s);
    uint8_t key[FX_MAX_KLEN];
    const size_t klen = fx_gen_key(s, key);
    const int rc = tidesdb_txn_delete(s->txn, fx_cf_handle(s->db, cf), key, klen);
    FUZZ_CHECK(rc == TDB_SUCCESS || rc == TDB_ERR_NOT_FOUND, "delete rc %d", rc);
    FUZZ_CHECK(fuzz_model_delete(s->model, cf, key, klen), "model delete");
}

/* a bound over the key alphabet, so an interval meets the keys the fuzzer writes */
static size_t fx_gen_bound(fx_state_t *s, uint8_t *bound)
{
    const size_t len = (size_t)(fx_byte(s) % FX_MAX_BOUND_LEN) + 1;
    for (size_t i = 0; i < len; i++) bound[i] = (uint8_t)('a' + (fx_byte(s) % FX_KEY_ALPHABET));
    return len;
}

static void fx_op_delete_range(fx_state_t *s)
{
    fx_ensure_txn(s);
    const char *cf = fx_pick_cf(s);
    uint8_t a[FX_MAX_BOUND_LEN];
    uint8_t b[FX_MAX_BOUND_LEN];
    const size_t alen = fx_gen_bound(s, a);
    const size_t blen = fx_gen_bound(s, b);

    /* the smaller of the two is the lower bound. two equal bounds describe an interval covering
     * nothing, which the engine refuses, so that pair runs to the end of the family instead */
    const int order = fuzz_key_cmp(a, alen, b, blen);
    const uint8_t *lo = order <= 0 ? a : b;
    const size_t lo_size = order <= 0 ? alen : blen;
    const uint8_t *hi = order <= 0 ? b : a;
    size_t hi_size = order <= 0 ? blen : alen;
    const int open_above = fx_byte(s) % FX_OPEN_ABOVE_TABLE == 0;
    if (order == 0 || open_above) hi_size = 0;

    const int rc = tidesdb_txn_delete_range(s->txn, fx_cf_handle(s->db, cf), lo, lo_size,
                                            hi_size ? hi : NULL, hi_size);
    FUZZ_CHECK(rc == TDB_SUCCESS, "delete_range rc %d", rc);
    FUZZ_CHECK(fuzz_model_delete_range(s->model, cf, lo, lo_size, hi_size ? hi : NULL, hi_size),
               "model delete_range");
    fx_op_history_record("  delete_range cf %s lo %.*s hi %.*s", cf, (int)lo_size, (const char *)lo,
                         (int)hi_size, hi_size ? (const char *)hi : "");
    if (s->verbose)
        fprintf(stderr, "    delete_range cf %s lo %.*s hi %.*s\n", cf, (int)lo_size,
                (const char *)lo, (int)hi_size, hi_size ? (const char *)hi : "");
}

static void fx_op_delete_prefix(fx_state_t *s)
{
    fx_ensure_txn(s);
    const char *cf = fx_pick_cf(s);
    uint8_t prefix[FX_MAX_BOUND_LEN];
    const size_t prefix_size = fx_gen_bound(s, prefix);
    const int rc = tidesdb_txn_delete_prefix(s->txn, fx_cf_handle(s->db, cf), prefix, prefix_size);
    FUZZ_CHECK(rc == TDB_SUCCESS, "delete_prefix rc %d", rc);
    FUZZ_CHECK(fuzz_model_delete_prefix(s->model, cf, prefix, prefix_size), "model delete_prefix");
    fx_op_history_record("  delete_prefix cf %s prefix %.*s", cf, (int)prefix_size,
                         (const char *)prefix);
    if (s->verbose)
        fprintf(stderr, "    delete_prefix cf %s prefix %.*s\n", cf, (int)prefix_size,
                (const char *)prefix);
}

static void fx_op_contains(fx_state_t *s)
{
    fx_ensure_txn(s);
    const char *cf = fx_pick_cf(s);
    uint8_t key[FX_MAX_KLEN];
    const size_t klen = fx_gen_key(s, key);
    const int rc = tidesdb_txn_contains(s->txn, fx_cf_handle(s->db, cf), key, klen);
    const uint8_t *mv = NULL;
    size_t mvlen = 0;
    const int present = fuzz_model_get(s->model, cf, key, klen, &mv, &mvlen);
    if (rc == TDB_SUCCESS)
        FUZZ_CHECK(present, "contains: db says present, model absent");
    else
    {
        FUZZ_CHECK(rc == TDB_ERR_NOT_FOUND, "contains rc %d", rc);
        FUZZ_CHECK(!present, "contains: db says absent, model present");
    }
}

/* ===== savepoints ===== */

static void fx_savepoint_name(fx_state_t *s, char *name)
{
    snprintf(name, FX_NAME_LEN, "sp%d", fx_byte(s) % 4);
}

static void fx_op_savepoint(fx_state_t *s)
{
    fx_ensure_txn(s);
    char name[FX_NAME_LEN];
    fx_savepoint_name(s, name);
    FUZZ_CHECK(tidesdb_txn_savepoint(s->txn, name) == TDB_SUCCESS, "savepoint");
    FUZZ_CHECK(fuzz_model_savepoint(s->model, name), "model savepoint");
}

static void fx_op_rollback_to(fx_state_t *s)
{
    if (!s->txn) return;
    char name[FX_NAME_LEN];
    fx_savepoint_name(s, name);
    const int rc = tidesdb_txn_rollback_to_savepoint(s->txn, name);
    const int mrc = fuzz_model_rollback_to(s->model, name);
    FUZZ_CHECK((rc == TDB_SUCCESS) == (mrc == 1), "rollback_to agreement rc %d mrc %d", rc, mrc);
}

static void fx_op_release(fx_state_t *s)
{
    if (!s->txn) return;
    char name[FX_NAME_LEN];
    fx_savepoint_name(s, name);
    const int rc = tidesdb_txn_release_savepoint(s->txn, name);
    const int mrc = fuzz_model_release(s->model, name);
    FUZZ_CHECK((rc == TDB_SUCCESS) == (mrc == 1), "release agreement rc %d mrc %d", rc, mrc);
}

static void fx_op_iter(fx_state_t *s)
{
    fx_commit_txn(s); /* settle so the committed view matches the model with no buffer */
    fx_verify_cf(s, s->db, fx_pick_cf(s));
}

/* ===== structural operations (applied to the database only; must not change results) ===== */

static void fx_op_flush(fx_state_t *s)
{
    fx_commit_txn(s);
    /* a backlog that outlasts the flush wait reports locked, which is a pacing outcome rather than
     * a fault. anything else means the flush path itself failed, and swallowing it would let a run
     * where every flush fails look exactly like a healthy one */
    const int rc = tidesdb_flush_memtable(s->db);
    FUZZ_CHECK(rc == TDB_SUCCESS || rc == TDB_ERR_LOCKED, "flush rc %d", rc);
}

static void fx_op_compact(fx_state_t *s)
{
    const char *cf = fx_pick_cf(s);
    fx_commit_txn(s);
    const int rc = tidesdb_compact(s->db, fx_cf_handle(s->db, cf));
    FUZZ_CHECK(rc == TDB_SUCCESS || rc == TDB_ERR_LOCKED, "compact rc %d", rc);
    fx_verify_cf(s, s->db, cf);
}

static void fx_op_compact_range(fx_state_t *s)
{
    const char *cf = fx_pick_cf(s);
    uint8_t a[FX_MAX_KLEN], b[FX_MAX_KLEN];
    const size_t al = fx_gen_key(s, a);
    const size_t bl = fx_gen_key(s, b);
    fx_commit_txn(s);
    const int rc = tidesdb_compact_range(s->db, fx_cf_handle(s->db, cf), a, al, b, bl);
    FUZZ_CHECK(rc == TDB_SUCCESS || rc == TDB_ERR_LOCKED || rc == TDB_ERR_BUSY,
               "compact_range rc %d", rc);
    fx_verify_cf(s, s->db, cf);
}

static void fx_op_checkpoint(fx_state_t *s)
{
    fx_commit_txn(s);
    /* a checkpoint flushes first, so it inherits the same locked outcome; every other code is a
     * failure of the fsync or manifest commit behind it */
    const int rc = tidesdb_checkpoint(s->db);
    FUZZ_CHECK(rc == TDB_SUCCESS || rc == TDB_ERR_LOCKED, "checkpoint rc %d", rc);
}

static void fx_op_sync_wal(fx_state_t *s)
{
    /* the barrier either lands or the write-ahead log could not be fsynced, and there is no benign
     * middle outcome to tolerate */
    FUZZ_CHECK(tidesdb_sync_wal(s->db) == TDB_SUCCESS, "sync_wal failed");
}

static void fx_op_vlog_gc(fx_state_t *s)
{
    const char *cf = fx_pick_cf(s);
    fx_commit_txn(s);
    engine_vlog_gc(s->db);
    fx_verify_cf(s, s->db, cf);
}

/* ===== column-family lifecycle ===== */

/* rebuild the harness's live cf name list from the model so it and the database stay in step */
static void fx_refresh_cf_names(fx_state_t *s)
{
    /* the two sets are compared both ways. checking only that every database family is known would
     * miss a family the engine lost, since the harness then adopts the database's shorter list and
     * never verifies the missing one again */
    char **names = NULL;
    int count = 0;
    FUZZ_CHECK(tidesdb_list_column_families(s->db, &names, &count) == TDB_SUCCESS, "list cfs");
    FUZZ_CHECK(count >= 1 && count <= FX_MAX_CFS, "cf count %d out of range", count);
    FUZZ_CHECK(count == fuzz_model_cf_count(s->model), "db has %d cfs, model has %d", count,
               fuzz_model_cf_count(s->model));
    for (int i = 0; i < count; i++)
        FUZZ_CHECK(fuzz_model_cf_exists(s->model, names[i]), "db cf %s absent from model",
                   names[i]);
    for (int i = 0; i < fuzz_model_cf_count(s->model); i++)
    {
        const char *mname = fuzz_model_cf_name_at(s->model, i);
        int seen = 0;
        for (int j = 0; j < count && !seen; j++) seen = strcmp(mname, names[j]) == 0;
        FUZZ_CHECK(seen, "model cf %s absent from db", mname);
    }
    s->cf_count = count;
    for (int i = 0; i < count; i++)
    {
        snprintf(s->cf_names[i], FX_NAME_LEN, "%s", names[i]);
        free(names[i]);
    }
    free(names);
}

/* the encodings this build actually carries, filled once and drawn from when a family is created or
 * reconfigured. a build without a codec must not have families configured for it, since that is a
 * rejected configuration rather than anything the engine should survive */
static uint8_t fx_codecs[4];
static int fx_codec_count;

static void fx_init_codecs(void)
{
    static const tidesdb_compression_algorithm_t all[] = {TDB_COMPRESS_SNAPPY, TDB_COMPRESS_LZ4,
                                                          TDB_COMPRESS_ZSTD, TDB_COMPRESS_LZ4_FAST};
    fx_codec_count = 0;
    for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); i++)
        if (tidesdb_compression_available(all[i])) fx_codecs[fx_codec_count++] = (uint8_t)all[i];
}

/* give the family an encoding pipeline drawn from the input -- none, one stage, or two. encodings
 * are meant to be transparent, so the model does not track them and the oracle compares the same
 * bytes either way; what this exercises is that a value or a node written through a chain comes
 * back through it, across a flush, a compaction, and a reopen */
static void fx_draw_pipeline(fx_state_t *s, tidesdb_column_family_config_t *cc)
{
    cc->encoding_count = 0;
    if (fx_codec_count == 0) return;

    const int stages = (int)(fx_byte(s) % 3); /* 0, 1 or 2 */
    for (int i = 0; i < stages; i++)
        cc->encoding_pipeline[cc->encoding_count++] = fx_codecs[fx_byte(s) % fx_codec_count];
}

static tidesdb_column_family_config_t fx_cf_config(fx_state_t *s)
{
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    fx_draw_pipeline(s, &cc);
    return cc;
}

static void fx_op_cf_create(fx_state_t *s)
{
    fx_commit_txn(s);
    fx_settle_prepared(s);
    char name[FX_NAME_LEN];
    snprintf(name, sizeof(name), "c%d", fx_byte(s) % FX_MAX_CFS);
    tidesdb_column_family_config_t cc = fx_cf_config(s);
    const int rc = tidesdb_create_column_family(s->db, name, &cc);
    const int existed = fuzz_model_cf_exists(s->model, name);
    if (rc == TDB_SUCCESS)
    {
        FUZZ_CHECK(!existed, "create: db created an existing cf %s", name);
        FUZZ_CHECK(fuzz_model_cf_create(s->model, name), "model create");
    }
    else
        FUZZ_CHECK(rc == TDB_ERR_EXISTS && existed, "create rc %d existed %d", rc, existed);
    fx_refresh_cf_names(s);
}

/* a closed database owns no sstables, so the live handle count must come back to what it was when
 * this run's database opened. checking at every close rather than once at the end is what makes a
 * failure answerable -- the leak is then inside the operations since the previous close rather than
 * anywhere in the run -- and the leak checker is asked for the allocation's stack while it is still
 * there to describe rather than at process exit with every trace gone */
void fx_check_handles(fx_state_t *s, const char *where)
{
    if (sstable_live_handles() == s->handles_at_open)
    {
        /* a layout holds a reference on every sstable it lists, so one that is neither published
         * nor on the retire list keeps a handle alive on its own. checking both says which of the
         * two went wrong rather than leaving it to be inferred from a refcount */
        if (level_live_layouts() == s->layouts_at_open) return;
        fprintf(stderr, "LEAK at %s: %lld layouts, expected %lld\n", where,
                (long long)level_live_layouts(), (long long)s->layouts_at_open);
        FUZZ_CHECK(0, "leaked %lld level layouts at %s",
                   (long long)(level_live_layouts() - s->layouts_at_open), where);
        return;
    }
    fprintf(stderr, "  layouts %lld, expected %lld\n", (long long)level_live_layouts(),
            (long long)s->layouts_at_open);

    fprintf(stderr, "LEAK at %s: %lld live, expected %lld\n", where,
            (long long)sstable_live_handles(), (long long)s->handles_at_open);
    FUZZ_CHECK(0, "leaked %lld sstable handles at %s",
               (long long)(sstable_live_handles() - s->handles_at_open), where);
}

static void fx_op_cf_drop(fx_state_t *s)
{
    fx_commit_txn(s);
    fx_settle_prepared(s);
    if (s->cf_count <= 1) return; /* keep at least one family so data ops always have a target */
    const char *name = fx_pick_cf(s);
    char copy[FX_NAME_LEN];
    snprintf(copy, sizeof(copy), "%s", name);
    FUZZ_CHECK(tidesdb_drop_column_family(s->db, copy) == TDB_SUCCESS, "drop %s", copy);
    FUZZ_CHECK(fuzz_model_cf_drop(s->model, copy), "model drop %s", copy);
    fx_refresh_cf_names(s);
}

static void fx_op_cf_rename(fx_state_t *s)
{
    fx_commit_txn(s);
    fx_settle_prepared(s);
    const char *old_name = fx_pick_cf(s);
    char from[FX_NAME_LEN], to[FX_NAME_LEN];
    snprintf(from, sizeof(from), "%s", old_name);
    snprintf(to, sizeof(to), "c%d", fx_byte(s) % FX_MAX_CFS);
    const int rc = tidesdb_rename_column_family(s->db, from, to);
    /* the engine rejects renaming onto any existing name, including the source's own -- rename(x,
     * x) is TDB_ERR_EXISTS -- so a taken target (same name included) is the failing case */
    const int taken = fuzz_model_cf_exists(s->model, to);
    if (rc == TDB_SUCCESS)
    {
        FUZZ_CHECK(!taken, "rename onto an existing cf %s", to);
        FUZZ_CHECK(fuzz_model_cf_rename(s->model, from, to), "model rename");
    }
    else
        /* a compaction that holds the family for the whole quiesce wait refuses the rename, which
         * leaves both the db and the model untouched */
        FUZZ_CHECK(rc == TDB_ERR_LOCKED || (rc == TDB_ERR_EXISTS && taken), "rename rc %d taken %d",
                   rc, taken);
    fx_refresh_cf_names(s);
}

/* change a live family's encoding pipeline. this is the case a separated value's self-description
 * exists for: compaction carries a value forward by id without re-encoding it, so after this the
 * sstable referencing a value can record a different pipeline than the one that wrote it, and a
 * value described by anything other than its own bytes would decode with the wrong chain */
static void fx_op_cf_reconfig(fx_state_t *s)
{
    if (getenv("FXNORECONF")) return;
    fx_commit_txn(s);
    const char *name = fx_pick_cf(s);
    if (!name) return;
    tidesdb_column_family_t *cf = fx_cf_handle(s->db, name);
    if (!cf) return;

    tidesdb_cf_stats_t st;
    if (tidesdb_get_cf_stats(cf, &st) != TDB_SUCCESS) return;
    tidesdb_column_family_config_t cc = st.config;
    fx_draw_pipeline(s, &cc);

    /* a family held by a compaction reports locked, which is the contract rather than a failure */
    const int rc = tidesdb_cf_update_runtime_config(s->db, cf, &cc, 1);
    FUZZ_CHECK(rc == TDB_SUCCESS || rc == TDB_ERR_LOCKED, "cf reconfig rc %d", rc);
}

static void fx_op_cf_clone(fx_state_t *s)
{
    fx_commit_txn(s);
    fx_settle_prepared(s);
    if (s->cf_count >= FX_MAX_CFS) return;
    const char *src = fx_pick_cf(s);
    char from[FX_NAME_LEN], to[FX_NAME_LEN];
    snprintf(from, sizeof(from), "%s", src);
    snprintf(to, sizeof(to), "c%d", fx_byte(s) % FX_MAX_CFS);
    const int rc = tidesdb_clone_column_family(s->db, from, to);
    const int taken = fuzz_model_cf_exists(s->model, to);
    if (rc == TDB_SUCCESS)
    {
        FUZZ_CHECK(!taken, "clone onto an existing cf %s", to);
        FUZZ_CHECK(fuzz_model_cf_clone(s->model, from, to), "model clone");
    }
    else
        /* a compaction that holds either family for the whole quiesce wait refuses the clone, which
         * leaves both the db and the model untouched */
        FUZZ_CHECK(rc == TDB_ERR_LOCKED || (rc == TDB_ERR_EXISTS && taken), "clone rc %d taken %d",
                   rc, taken);
    fx_refresh_cf_names(s);
}

/* ===== operation history =====
 *
 * the last operations dispatched, kept in memory. a run that traces to stderr as it goes is slowed
 * enough by the writing to change how it interleaves with the flush and compaction threads, and a
 * divergence that only appears at full speed then stops appearing at all. so the history costs a
 * formatted copy into a fixed slot and is read only once something has already gone wrong */
#define FX_OP_HISTORY      64
#define FX_OP_HISTORY_TEXT 96

static char fx_op_history_text[FX_OP_HISTORY][FX_OP_HISTORY_TEXT];
static uint64_t fx_op_history_count;

void fx_op_history_record(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    (void)vsnprintf(fx_op_history_text[fx_op_history_count % FX_OP_HISTORY], FX_OP_HISTORY_TEXT,
                    fmt, args);
    va_end(args);
    fx_op_history_count++;
}

void fx_op_history_dump(void)
{
    const uint64_t have = fx_op_history_count < FX_OP_HISTORY ? fx_op_history_count : FX_OP_HISTORY;
    fprintf(stderr, "\nlast %llu operations, oldest first\n", (unsigned long long)have);
    for (uint64_t i = fx_op_history_count - have; i < fx_op_history_count; i++)
        fprintf(stderr, "  %6llu  %s\n", (unsigned long long)i,
                fx_op_history_text[i % FX_OP_HISTORY]);
    fflush(stderr);
}

/* operations named in TIDESDB_FUZZ_SKIP are not dispatched, so a divergence can be bisected over
 * the operation stream rather than reasoned about. a run that stops diverging once a class of
 * operation is withheld has named the class that has to be involved, which is a far cheaper
 * question to answer than what the mechanism is */
static int fx_op_skipped(const char *name)
{
    const char *skip = getenv("TIDESDB_FUZZ_SKIP");
    if (!skip || !*skip) return 0;
    const size_t n = strlen(name);
    for (const char *p = skip; *p;)
    {
        const char *end = strchr(p, ',');
        const size_t len = end ? (size_t)(end - p) : strlen(p);
        if (len == n && strncmp(p, name, n) == 0) return 1;
        if (!end) break;
        p = end + 1;
    }
    return 0;
}

/* ===== dispatch and run ===== */

static void fx_dispatch(fx_state_t *s, fx_op_t op)
{
    switch (op)
    {
        case FX_PUT:
            fx_op_put(s);
            break;
        case FX_GET:
            fx_op_get(s);
            break;
        case FX_DELETE:
            fx_op_delete(s);
            break;
        case FX_DELETE_RANGE:
            fx_op_delete_range(s);
            break;
        case FX_DELETE_PREFIX:
            fx_op_delete_prefix(s);
            break;
        case FX_CONTAINS:
            fx_op_contains(s);
            break;
        case FX_BEGIN:
            fx_commit_txn(s);
            fx_ensure_txn(s);
            break;
        case FX_COMMIT:
            fx_commit_txn(s);
            break;
        case FX_ROLLBACK:
            fx_rollback_txn(s);
            break;
        case FX_SAVEPOINT:
            fx_op_savepoint(s);
            break;
        case FX_ROLLBACK_TO:
            fx_op_rollback_to(s);
            break;
        case FX_RELEASE:
            fx_op_release(s);
            break;
        case FX_ITER:
            fx_op_iter(s);
            break;
        case FX_FLUSH:
            fx_op_flush(s);
            break;
        case FX_COMPACT:
            fx_op_compact(s);
            break;
        case FX_COMPACT_RANGE:
            fx_op_compact_range(s);
            break;
        case FX_CHECKPOINT:
            fx_op_checkpoint(s);
            break;
        case FX_SYNC_WAL:
            fx_op_sync_wal(s);
            break;
        case FX_VLOG_GC:
            fx_op_vlog_gc(s);
            break;
        case FX_CF_CREATE:
            fx_op_cf_create(s);
            break;
        case FX_CF_DROP:
            fx_op_cf_drop(s);
            break;
        case FX_CF_RENAME:
            fx_op_cf_rename(s);
            break;
        case FX_CF_CLONE:
            fx_op_cf_clone(s);
            break;
        case FX_REOPEN:
            fx_op_reopen(s);
            break;
        case FX_BACKUP:
            fx_op_backup(s);
            break;
        case FX_PREPARE:
            fx_op_prepare(s);
            break;
        case FX_COMMIT_PREPARED:
            fx_op_commit_prepared(s);
            break;
        case FX_ROLLBACK_PREPARED:
            fx_op_rollback_prepared(s);
            break;
        case FX_CF_RECONFIG:
            fx_op_cf_reconfig(s);
            break;
        case FX_TXN_RESET:
            fx_op_txn_reset(s);
            break;
        default:
            break;
    }
}

static const char *FX_OP_NAMES[] = {
    "PUT",     "GET",       "DELETE",          "DELETE_RANGE",      "DELETE_PREFIX", "CONTAINS",
    "BEGIN",   "COMMIT",    "ROLLBACK",        "SAVEPOINT",         "ROLLBACK_TO",   "RELEASE",
    "ITER",    "FLUSH",     "COMPACT",         "COMPACT_RANGE",     "CHECKPOINT",    "SYNC_WAL",
    "VLOG_GC", "CF_CREATE", "CF_DROP",         "CF_RENAME",         "CF_CLONE",      "REOPEN",
    "BACKUP",  "PREPARE",   "COMMIT_PREPARED", "ROLLBACK_PREPARED", "TXN_RESET",     "CF_RECONFIG"};

/* the names are a table parallel to the enumeration, and a new operation that reaches one but not
 * the other reads off the end of this. the two are tied together here rather than left to be
 * noticed at the point a failing run tries to name the operation it stopped on */
_Static_assert(sizeof(FX_OP_NAMES) / sizeof(FX_OP_NAMES[0]) == FX_OP_COUNT,
               "the operation name table carries one name per operation");

int fuzz_run(const uint8_t *data, size_t size, int sync_mode)
{
    fx_state_t s;
    memset(&s, 0, sizeof(s));
    s.data = data;
    s.size = size;
    s.sync_mode = sync_mode;
    s.verbose = getenv("TIDESDB_FUZZ_VERBOSE") != NULL;
    fx_init_codecs();

    s.log_level = TDB_LOG_NONE;
    const char *lvl = getenv("TIDESDB_FUZZ_LOG");
    if (lvl)
    {
        if (strcmp(lvl, "trace") == 0)
            s.log_level = TDB_LOG_TRACE;
        else if (strcmp(lvl, "info") == 0)
            s.log_level = TDB_LOG_INFO;
        else
            s.log_level = TDB_LOG_WARN;
    }
    /* the level is drawn from the input, which silences the engine on most runs -- fine for a
     * fuzzer and useless for diagnosing one, so it can be pinned from the environment */
    if (getenv("TIDESDB_FUZZ_LOG_WARN")) s.log_level = TDB_LOG_WARN;
    atomic_store(&_tidesdb_log_level, s.log_level);
    /* fuzz_run is called once per iteration, so the sink is opened once per process rather than
     * reopened (and leaked) on every one */
    static int sink_opened = 0;
    const char *logfile = getenv("TIDESDB_FUZZ_LOG_FILE");
    if (logfile && !sink_opened)
    {
        FILE *lf = fopen(logfile, "w");
        if (lf) tidesdb_log_set_sink(lf, 0, logfile);
        sink_opened = 1;
    }

    const char *base = getenv("TIDESDB_FUZZ_DIR");
    s.handles_at_open = sstable_live_handles();
    s.layouts_at_open = level_live_layouts();
    snprintf(s.db_dir, sizeof(s.db_dir), "%s%sfuzzdb", base ? base : ".", PATH_SEPARATOR);
    (void)remove_directory(s.db_dir);

    if (getenv("TIDESDB_FUZZ_DUMP"))
    {
        char dpath[FX_PATH_LEN + 16];
        snprintf(dpath, sizeof(dpath), "%s%slast_input.bin", base ? base : ".", PATH_SEPARATOR);
        FILE *df = fopen(dpath, "wb");
        if (df)
        {
            (void)fwrite(data, 1, size, df);
            fclose(df);
        }
    }

    tidesdb_config_t cfg = fx_db_config(&s, s.db_dir);
    if (tidesdb_open(&cfg, &s.db) != TDB_SUCCESS) return 0;

    s.model = fuzz_model_create();
    FUZZ_CHECK(s.model != NULL, "model create");

    /* start with one column family both sides agree on */
    tidesdb_column_family_config_t cc = fx_cf_config(&s);
    FUZZ_CHECK(tidesdb_create_column_family(s.db, "c0", &cc) == TDB_SUCCESS, "seed cf");
    FUZZ_CHECK(fuzz_model_cf_create(s.model, "c0"), "seed model cf");
    snprintf(s.cf_names[0], FX_NAME_LEN, "c0");
    s.cf_count = 1;

    for (int n = 0; n < FX_MAX_OPS && !fx_exhausted(&s); n++)
    {
        const fx_op_t op = FX_OP_TABLE[fx_byte(&s) % FX_OP_TABLE_LEN];
        if (fx_op_skipped(FX_OP_NAMES[op])) continue;
        if (s.verbose) fprintf(stderr, "op %d: %s\n", n, FX_OP_NAMES[op]);
        fx_op_history_record("op %d %s", n, FX_OP_NAMES[op]);
        fx_dispatch(&s, op);
    }

    /* a final full comparison over every family */
    fx_full_verify(&s, s.db);

    fx_rollback_txn(&s);
    /* an undecided prepare is durable by design, so the run only drops its handle and lets the
     * directory teardown below take the log with it */
    if (s.prepared) tidesdb_txn_free(s.prepared);
    FUZZ_CHECK(tidesdb_close(s.db) == TDB_SUCCESS, "final close");

    fx_check_handles(&s, "final close");
    fuzz_model_free(s.model);
    (void)remove_directory(s.db_dir);
    return 0;
}
