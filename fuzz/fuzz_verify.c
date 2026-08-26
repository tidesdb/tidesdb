/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <ctype.h>
#include <string.h>

#include "compat.h" /* usleep */
#include "fuzz_harness_internal.h"

/* ===== iteration oracle =====
 *
 * the scans below run in a transaction of their own that never writes, and the caller commits the
 * in-flight one first, so what they see is the committed state. that is an arrangement of this
 * harness rather than a property of iterators -- a scan does fold its own transaction's buffered
 * writes over the snapshot, which is why the verification transaction is kept empty */

/* how many leading bytes of a key or value a divergence report spells out */
#define FX_DUMP_MAX_BYTES 32

/* spell one key or value out as hex with a printable rendering beside it, so a divergence names the
 * bytes involved instead of only a position */
static void fx_dump_bytes(const char *label, const uint8_t *b, size_t n)
{
    const size_t shown = n < FX_DUMP_MAX_BYTES ? n : FX_DUMP_MAX_BYTES;
    fprintf(stderr, "    %s len %zu hex ", label, n);
    for (size_t i = 0; i < shown; i++) fprintf(stderr, "%02x", b[i]);
    fprintf(stderr, " text \"");
    for (size_t i = 0; i < shown; i++) fputc(isprint(b[i]) ? b[i] : '.', stderr);
    fprintf(stderr, "%s\"\n", shown < n ? "..." : "");
}

/* report a diverging scan in full -- the model's whole visible set and the database entry that did
 * not match it -- so the offending key can be traced back through the engine log */
static void fx_dump_divergence(const char *cf, const fuzz_model_kv_t *kv, size_t kn, size_t at,
                               const uint8_t *k, size_t kl, const uint8_t *v, size_t vl)
{
    fprintf(stderr, "\nscan divergence in cf %s at index %zu, model holds %zu keys\n", cf, at, kn);
    for (size_t i = 0; i < kn; i++)
    {
        fprintf(stderr, "  model[%zu]\n", i);
        fx_dump_bytes("key", kv[i].key, kv[i].klen);
        fx_dump_bytes("val", kv[i].val, kv[i].vlen);
    }
    if (k)
    {
        fprintf(stderr, "  database entry at %zu, absent from the model above\n", at);
        fx_dump_bytes("key", k, kl);
        if (v) fx_dump_bytes("val", v, vl);
    }
    fflush(stderr);
}

/* bounded attempts when opening a scan, since the reader fd budget and a moving source set are both
 * reported as locked, which asks the caller to come back rather than saying the read failed */
#define FX_ITER_OPEN_TRIES 64

/* pause between attempts, long enough for a compaction to release the descriptors it holds */
#define FX_ITER_OPEN_BACKOFF_US 1000

/* open a scan, waiting out transient back pressure. returns the iterator, or NULL when the engine
 * stayed locked for every attempt, in which case there is nothing to compare and the caller skips
 */
static tidesdb_iter_t *fx_iter_open(tidesdb_txn_t *rt, tidesdb_column_family_t *cf,
                                    const char *name)
{
    for (int t = 0; t < FX_ITER_OPEN_TRIES; t++)
    {
        tidesdb_iter_t *it = NULL;
        const int rc = tidesdb_iter_new(rt, cf, &it);
        if (rc == TDB_SUCCESS) return it;
        FUZZ_CHECK(rc == TDB_ERR_LOCKED, "iter_new cf %s rc %d", name, rc);
        usleep(FX_ITER_OPEN_BACKOFF_US);
    }
    return NULL;
}

/* verify a forward scan over db's cf equals the sorted model set kv[0..kn) */
static void fx_iter_forward(tidesdb_t *db, tidesdb_txn_t *rt, const char *cf,
                            const fuzz_model_kv_t *kv, size_t kn)
{
    tidesdb_iter_t *it = fx_iter_open(rt, fx_cf_handle(db, cf), cf);
    if (!it) return;
    (void)tidesdb_iter_seek_to_first(it);
    size_t i = 0;
    while (tidesdb_iter_valid(it))
    {
        uint8_t *k = NULL, *v = NULL;
        size_t kl = 0, vl = 0;
        const int kvrc = tidesdb_iter_key_value(it, &k, &kl, &v, &vl);
        /* a failed resolve leaves no entry to show, so the model's expectation at this position is
         * what names the key whose value the engine could not produce */
        if (kvrc != TDB_SUCCESS) fx_dump_divergence(cf, kv, kn, i, NULL, 0, NULL, 0);
        FUZZ_CHECK(kvrc == TDB_SUCCESS, "iter kv rc %d at %zu", kvrc, i);
        /* dump before the assertions below fire, since each of them aborts the process */
        if (i >= kn || kl != kv[i].klen || memcmp(k, kv[i].key, kl) != 0 ||
            !fuzz_value_eq(v, vl, kv[i].val, kv[i].vlen))
            fx_dump_divergence(cf, kv, kn, i, k, kl, v, vl);
        FUZZ_CHECK(i < kn, "iter has more keys than model");
        FUZZ_CHECK(kl == kv[i].klen && memcmp(k, kv[i].key, kl) == 0, "iter key mismatch at %zu",
                   i);
        FUZZ_CHECK(fuzz_value_eq(v, vl, kv[i].val, kv[i].vlen), "iter value mismatch at %zu", i);
        free(k);
        free(v);
        i++;
        (void)tidesdb_iter_next(it);
    }
    if (i != kn) fx_dump_divergence(cf, kv, kn, i, NULL, 0, NULL, 0);
    FUZZ_CHECK(i == kn, "iter saw %zu keys, model has %zu", i, kn);
    tidesdb_iter_free(it);
}

/* verify a backward scan visits the same set in reverse */
static void fx_iter_backward(tidesdb_t *db, tidesdb_txn_t *rt, const char *cf,
                             const fuzz_model_kv_t *kv, size_t kn)
{
    tidesdb_iter_t *it = fx_iter_open(rt, fx_cf_handle(db, cf), cf);
    if (!it) return;
    (void)tidesdb_iter_seek_to_last(it);
    size_t i = 0;
    while (tidesdb_iter_valid(it))
    {
        uint8_t *k = NULL, *v = NULL;
        size_t kl = 0, vl = 0;
        FUZZ_CHECK(tidesdb_iter_key_value(it, &k, &kl, &v, &vl) == TDB_SUCCESS, "iter kv rev");
        FUZZ_CHECK(i < kn, "reverse iter overruns model");
        const fuzz_model_kv_t *e = &kv[kn - 1 - i];
        FUZZ_CHECK(kl == e->klen && memcmp(k, e->key, kl) == 0, "reverse key mismatch at %zu", i);
        FUZZ_CHECK(fuzz_value_eq(v, vl, e->val, e->vlen), "reverse value mismatch at %zu", i);
        free(k);
        free(v);
        i++;
        (void)tidesdb_iter_prev(it);
    }
    FUZZ_CHECK(i == kn, "reverse iter saw %zu keys, model has %zu", i, kn);
    tidesdb_iter_free(it);
}

/* verify a seek lands on the first key >= the target, matching the model */
static void fx_iter_seek(fx_state_t *s, tidesdb_txn_t *rt, const char *cf,
                         const fuzz_model_kv_t *kv, size_t kn)
{
    uint8_t key[FX_MAX_KLEN];
    const size_t klen = fx_gen_key(s, key);
    size_t expect = 0;
    while (expect < kn && fuzz_key_cmp(kv[expect].key, kv[expect].klen, key, klen) < 0) expect++;

    tidesdb_iter_t *it = fx_iter_open(rt, fx_cf_handle(s->db, cf), cf);
    if (!it) return;
    (void)tidesdb_iter_seek(it, key, klen);
    if (expect < kn)
    {
        FUZZ_CHECK(tidesdb_iter_valid(it), "seek: model finds a key >= target, db does not");
        uint8_t *k = NULL;
        size_t kl = 0;
        FUZZ_CHECK(tidesdb_iter_key(it, &k, &kl) == TDB_SUCCESS, "seek key");
        FUZZ_CHECK(kl == kv[expect].klen && memcmp(k, kv[expect].key, kl) == 0,
                   "seek landed wrong");
        free(k);
    }
    else
        FUZZ_CHECK(!tidesdb_iter_valid(it), "seek: db finds a key past the model's largest");
    tidesdb_iter_free(it);
}

/* run every iteration check for a cf against the committed model, over a fresh read transaction */
void fx_verify_cf(fx_state_t *s, tidesdb_t *db, const char *cf)
{
    fuzz_model_kv_t *kv = NULL;
    size_t kn = 0;
    FUZZ_CHECK(fuzz_model_scan(s->model, cf, &kv, &kn), "model scan %s", cf);

    tidesdb_txn_t *rt = NULL;
    FUZZ_CHECK(tidesdb_txn_begin(db, &rt) == TDB_SUCCESS, "verify txn begin");
    fx_iter_forward(db, rt, cf, kv, kn);
    fx_iter_backward(db, rt, cf, kv, kn);
    if (db == s->db) fx_iter_seek(s, rt, cf, kv, kn); /* seek consumes input, only in the main db */
    (void)tidesdb_txn_commit(rt);
    tidesdb_txn_free(rt);
    free(kv);
}

/* scan every column family and confirm the whole database matches the model */
void fx_full_verify(fx_state_t *s, tidesdb_t *db)
{
    fx_commit_txn(s);
    for (int i = 0; i < s->cf_count; i++) fx_verify_cf(s, db, s->cf_names[i]);
}