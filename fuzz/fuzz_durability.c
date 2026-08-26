/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <stdio.h>
#include <string.h>

#include "base/errors.h" /* TDB_ERR_BUSY is engine-internal, not in the public db.h */
#include "compat.h"      /* remove_directory */
#include "db.h"
#include "fuzz_harness.h"
#include "fuzz_harness_internal.h"
#include "fuzz_model.h"

/* the operations that carry a batch or a whole database across a boundary it might not survive: the
 * two-phase protocol, which leaves a batch in doubt between the prepare and the decision, and the
 * reopen and backup that rebuild a database from what reached the disk. each one re-verifies the
 * entire model afterwards, since what they are asked to prove is that nothing was lost */

/* ===== two-phase commit ===== */

/* prepare the open transaction under a fresh xid. a write transaction becomes in-doubt and its
 * buffer must stay invisible until phase two; a read-only one finishes outright with no phase two
 */
void fx_op_prepare(fx_state_t *s)
{
    if (!s->txn || s->prepared) return; /* one prepared transaction at a time mirrors the model */

    uint8_t xid[FX_XID_LEN];
    for (size_t i = 0; i < sizeof(xid); i++) xid[i] = (uint8_t)('A' + (s->value_tag + i) % 26);
    s->value_tag++;

    /* a prepare runs the same write phase a commit does, so at any level that detects conflicts it
     * can be refused for the same one-sided reasons, and the transaction aborts rather than
     * becoming in doubt */
    int required = 0, allowed = 0;
    fx_conflict_expectation(s, &required, &allowed);
    const int rc = tidesdb_txn_prepare(s->txn, xid, sizeof(xid));
    if (rc == TDB_ERR_CONFLICT)
    {
        FUZZ_CHECK(allowed, "prepare refused at isolation %d, which runs no conflict detection",
                   (int)s->txn_iso);
        tidesdb_txn_free(s->txn);
        s->txn = NULL;
        fuzz_model_txn_rollback(s->model);
        if (s->verbose) fprintf(stderr, "    prepare refused, transaction aborted\n");
        return;
    }
    FUZZ_CHECK(rc == TDB_SUCCESS, "prepare rc %d", rc);

    if (s->verbose) fprintf(stderr, "    prepare rc %d\n", rc);
    if (fuzz_model_txn_prepare(s->model))
    {
        if (s->verbose) fprintf(stderr, "    prepare held a batch\n");
        s->prepared = s->txn;
        s->prepared_iso = s->txn_iso;
        s->prepared_recovered = 0;
        memcpy(s->prepared_xid, xid, sizeof(xid));
        s->prepared_xid_size = sizeof(xid);
    }
    else
    {
        /* a read-only prepare needs no phase two, so the handle is done */
        if (s->verbose) fprintf(stderr, "    prepare was read-only in the model\n");
        tidesdb_txn_free(s->txn);
    }
    s->txn = NULL;
}

void fx_op_commit_prepared(fx_state_t *s)
{
    if (!s->prepared) return;

    /* settle the open transaction first, because this is the one operation that commits a
     * *different* transaction while leaving the reader's alone. a reader at repeatable-read or
     * above holds a snapshot taken before this commit, so the engine correctly hides the batch from
     * it -- while the model keeps one latest-committed value per key and has no notion of who is
     * reading. comparing the two afterwards reports a key the reader is not entitled to see as a
     * lost write. every other commit path already ends the reader's transaction, which is why only
     * this one drifts; fx_op_reopen settles for the same reason */
    fx_commit_txn(s);

    const int rc = tidesdb_txn_commit_prepared(s->prepared);
    FUZZ_CHECK(rc == TDB_SUCCESS, "commit_prepared rc %d", rc);
    FUZZ_CHECK(fuzz_model_commit_prepared(s->model), "model commit_prepared");
    tidesdb_txn_free(s->prepared);
    s->prepared = NULL;
    s->prepared_xid_size = 0;
    s->prepared_recovered = 0;
}

void fx_op_rollback_prepared(fx_state_t *s)
{
    if (!s->prepared) return;
    const int rc = tidesdb_txn_rollback_prepared(s->prepared);
    FUZZ_CHECK(rc == TDB_SUCCESS, "rollback_prepared rc %d", rc);
    FUZZ_CHECK(fuzz_model_rollback_prepared(s->model), "model rollback_prepared");
    tidesdb_txn_free(s->prepared);
    s->prepared = NULL;
    s->prepared_xid_size = 0;
    s->prepared_recovered = 0;
}

/* after a reopen, an undecided prepare must come back listed under the same xid and still holding
 * an invisible batch. re-adopting it here keeps the harness able to decide it later, which is what
 * proves the whole recovery path rather than just that the record survived */
static void fx_readopt_prepared(fx_state_t *s)
{
    int count = -1;
    FUZZ_CHECK(tidesdb_recover_prepared(s->db, NULL, 0, &count) == TDB_SUCCESS, "recover count");

    if (!fuzz_model_prepared_open(s->model))
    {
        FUZZ_CHECK(count == 0, "recovered %d prepared, model has none", count);
        return;
    }

    FUZZ_CHECK(count == 1, "recovered %d prepared, model has one", count);
    tidesdb_prepared_txn_t found[FX_MAX_PREPARED];
    FUZZ_CHECK(tidesdb_recover_prepared(s->db, found, FX_MAX_PREPARED, &count) == TDB_SUCCESS,
               "recover list");
    FUZZ_CHECK(count == 1, "recover list returned %d", count);
    FUZZ_CHECK(found[0].xid_size == s->prepared_xid_size &&
                   memcmp(found[0].xid, s->prepared_xid, s->prepared_xid_size) == 0,
               "recovered xid does not match the prepared one");
    s->prepared = found[0].txn;
    s->prepared_recovered = 1;
}

/* decide any outstanding prepare before a column-family lifecycle operation. the model identifies a
 * family by name while the engine identifies it by id, so a prepared batch that spans a create,
 * drop or rename would apply to the id it captured while the model applied it to whatever holds the
 * name by then. the two are both right and disagree, which is a limit of the model rather than a
 * fault in the engine, so the harness keeps prepares clear of those operations */
void fx_settle_prepared(fx_state_t *s)
{
    if (s->prepared) fx_op_commit_prepared(s);
}

/* ===== durability: reopen and backup both re-verify the entire model ===== */

tidesdb_config_t fx_db_config(fx_state_t *s, char *path)
{
    tidesdb_config_t cfg = tidesdb_default_config();
    cfg.db_path = path;
    cfg.memtable_write_buffer_size = FX_WRITE_BUFFER;
    cfg.memtable_sync_mode = s->sync_mode == FUZZ_SYNC_FULL ? TDB_SYNC_FULL : TDB_SYNC_NONE;
    cfg.log_level = (tidesdb_log_level_t)s->log_level;
    return cfg;
}

void fx_op_reopen(fx_state_t *s)
{
    fx_commit_txn(s);
    /* an undecided prepare is meant to outlive this, so the handle is dropped without deciding it
     * and the database is asked to hand it back after the reopen */
    if (s->prepared)
    {
        tidesdb_txn_free(s->prepared);
        s->prepared = NULL;
    }
    FUZZ_CHECK(tidesdb_close(s->db) == TDB_SUCCESS, "reopen close");
    fx_check_handles(s, "reopen");
    tidesdb_config_t cfg = fx_db_config(s, s->db_dir);
    FUZZ_CHECK(tidesdb_open(&cfg, &s->db) == TDB_SUCCESS, "reopen open");
    fx_readopt_prepared(s);
    fx_full_verify(s, s->db);
}

void fx_op_backup(fx_state_t *s)
{
    fx_commit_txn(s);
    char bdir[FX_PATH_LEN + 16];
    snprintf(bdir, sizeof(bdir), "%s_backup", s->db_dir);
    (void)remove_directory(bdir);

    const int rc = tidesdb_backup(s->db, bdir);
    FUZZ_CHECK(rc == TDB_SUCCESS || rc == TDB_ERR_BUSY, "backup rc %d", rc);
    if (rc == TDB_SUCCESS)
    {
        tidesdb_config_t cfg = fx_db_config(s, bdir);
        tidesdb_t *copy = NULL;
        FUZZ_CHECK(tidesdb_open(&cfg, &copy) == TDB_SUCCESS, "backup open");
        fx_full_verify(s, copy);
        FUZZ_CHECK(tidesdb_close(copy) == TDB_SUCCESS, "backup close");
    }
    (void)remove_directory(bdir);
}
