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

#include "../src/column_family/column_family.h" /* cf_range_tombstone_covering, for the diagnosis below */
#include "../src/column_family/level/level_set.h" /* level_set_collect_all, to enumerate the tables */
#include "../src/engine/engine_internal.h"        /* db->l0, for the memtable interrogation */
#include "../src/memtable/memtable.h"
#include "../src/sstable/sstable.h"      /* sstable_get_at_seq, to ask each one directly */
#include "base/encoding/serialization.h" /* tdb_build_prefixed_key */
#include "compat.h"                      /* usleep */
#include "fuzz_harness_internal.h"

/* ===== iteration oracle =====
 *
 * the scans below run in a transaction of their own that never writes, and the caller commits the
 * in-flight one first, so what they see is the committed state. that is an arrangement of this
 * harness rather than a property of iterators -- a scan does fold its own transaction's buffered
 * writes over the snapshot, which is why the verification transaction is kept empty */

/* how many leading bytes of a key or value a divergence report spells out */
#define FX_DUMP_MAX_BYTES 32

/* tables one divergence report enumerates before it stops, which is more than any family the
 * harness builds ever holds */
#define FX_DIAG_MAX_TABLES 64

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

/* the database currently being verified, so a divergence can interrogate it directly */
static tidesdb_t *fx_diag_db;
static const fuzz_model_t *fx_diag_model;

/* report a diverging scan in full -- the model's whole visible set and the database entry that did
 * not match it -- so the offending key can be traced back through the engine log */
static void fx_dump_divergence(const char *cf, const fuzz_model_kv_t *kv, size_t kn, size_t at,
                               const uint8_t *k, size_t kl, const uint8_t *v, size_t vl)
{
    fx_op_history_dump();
    fprintf(stderr, "\nscan divergence in cf %s at index %zu, model holds %zu keys\n", cf, at, kn);
    for (size_t i = 0; i < kn; i++)
    {
        fprintf(stderr, "  model[%zu]\n", i);
        fx_dump_bytes("key", kv[i].key, kv[i].klen);
        fx_dump_bytes("val", kv[i].val, kv[i].vlen);
    }
    if (k && fx_diag_db)
    {
        /* the model deleted this key and the database handed it back, so the question is whether
         * an interval covering it is still in any table the read would have consulted. asked at the
         * widest snapshot there is, so a yes means the read ignored an interval it had and a no
         * means no table carries one any more */
        cf_t *dcf = (cf_t *)tidesdb_get_column_family(fx_diag_db, cf);
        uint64_t tomb = 0;
        const int covered = dcf ? cf_range_tombstone_covering(dcf, k, kl, UINT64_MAX, &tomb) : -1;
        fprintf(stderr, "  a table covers this key %d (seq %llu)\n", covered,
                (unsigned long long)tomb);

        /* which table is handing the key back, and how many intervals that table carries. an
         * interval lives in the table it was written into, so a key that came back is either in a
         * table no interval covers or in one whose intervals went with a merge */
        if (dcf)
        {
            sstable_t *tabs[FX_DIAG_MAX_TABLES];
            const int nt = level_set_collect_all(dcf->levels, tabs, FX_DIAG_MAX_TABLES);
            fprintf(stderr, "  family holds %d tables\n", nt);
            for (int t = 0; t < nt && t < FX_DIAG_MAX_TABLES; t++)
            {
                uint8_t *tv = NULL;
                size_t tvl = 0;
                uint64_t voff = 0, tseq = 0;
                int64_t tttl = -1;
                uint8_t tdel = 0;
                const int hit = sstable_get_at_seq(tabs[t], k, kl, UINT64_MAX, &tv, &tvl, &voff,
                                                   &tseq, &tttl, &tdel) == TDB_SUCCESS;
                fprintf(stderr,
                        "    table %llu carries %d intervals, holds this key %d (seq %llu, deleted "
                        "%d)\n",
                        (unsigned long long)tabs[t]->id,
                        tabs[t]->range_tombstones
                            ? (int)range_tombstone_set_count(tabs[t]->range_tombstones)
                            : 0,
                        hit, (unsigned long long)tseq, (int)tdel);
                free(tv);
                if (sstable_unref(tabs[t])) sstable_close(tabs[t]);
            }
        }

        /* and what the model holds for it, which says whether the model deleted the key or never
         * had it at all */
        int mtomb = 0;
        uint64_t mseq = 0;
        const int held =
            fx_diag_model ? fuzz_model_debug_entry(fx_diag_model, cf, k, kl, &mtomb, &mseq) : -1;
        fprintf(stderr, "  model holds a version of this key %d (tombstone %d, seq %llu)\n", held,
                mtomb, (unsigned long long)mseq);

        /* and whether the engine agrees with itself. a point get that cannot find what the scan
         * just handed back is the read path disagreeing internally, which is a different fault
         * from the two of them agreeing on a key the model says is gone */
        /* the tables are only half the picture -- an interval still sitting in a memtable, or one
         * replayed into one, has not reached a table at all. ask each pinned memtable directly */
        if (fx_diag_db)
        {
            tidesdb_memtable_t *mts[32];
            int nm = 0;
            if (tidesdb_l0_pin_memtables(fx_diag_db->l0, mts, 32, &nm) == TDB_SUCCESS)
            {
                uint8_t pk[TDB_CF_PREFIX_SIZE + 64];
                const size_t pks = tdb_build_prefixed_key((uint32_t)((cf_t *)dcf)->cf_id, k,
                                                          kl < 64 ? kl : 64, pk);
                int hit = 0;
                uint64_t mt_seq = 0;
                for (int mi = 0; mi < nm; mi++)
                    if (tidesdb_memtable_range_tombstone_covering(fx_diag_db->l0, mts[mi], pk, pks,
                                                                  UINT64_MAX, &mt_seq))
                        hit = 1;
                fprintf(stderr, "  memtables pinned %d, any covers this key %d (seq %llu)\n", nm,
                        hit, (unsigned long long)mt_seq);
                tidesdb_l0_unpin_memtables(mts, nm);
            }
        }

        /* and what L0 holds for the key as a version rather than as interval coverage. a tombstone
         * sitting here that the read stack did not return is a read fault; nothing here at all
         * means the delete never reached a memtable, or was replayed away, and the live version the
         * tables hand back is simply the newest one that survives */
        {
            uint8_t *lv = NULL;
            size_t lvl = 0;
            uint64_t lvid = 0, lseq = 0;
            int64_t lttl = -1;
            uint8_t ldel = 0;
            const int lrc =
                tidesdb_l0_get_at_seq(fx_diag_db->l0, (uint32_t)((cf_t *)dcf)->cf_id, k, kl,
                                      UINT64_MAX, &lv, &lvl, &lvid, &lttl, &ldel, &lseq);
            fprintf(stderr, "  l0 holds this key rc %d (seq %llu, deleted %d, vlen %zu)\n", lrc,
                    (unsigned long long)lseq, (int)ldel, lvl);
            free(lv);
        }

        tidesdb_txn_t *gt = NULL;
        if (tidesdb_txn_begin(fx_diag_db, &gt) == TDB_SUCCESS)
        {
            uint8_t *gv = NULL;
            size_t gvl = 0;
            const int grc = tidesdb_txn_get(gt, fx_cf_handle(fx_diag_db, cf), k, kl, &gv, &gvl);
            fprintf(stderr, "  point get of the same key rc %d\n", grc);
            free(gv);
            (void)tidesdb_txn_rollback(gt);
            tidesdb_txn_free(gt);
        }
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
    fx_diag_db = db;
    fx_diag_model = s->model;

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