/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "compat.h"
#include "db.h"
#include "fuzz_model.h"
#include "xxhash.h" /* XXH3 128-bit state fingerprint, shared with the rest of the engine */

/* the crash/recovery harness exercises recovery from an abrupt kill: a child process commits under
 * a full sync barrier, the parent kills it at a chosen point, then reopens the database and checks
 * an exact-durable-prefix invariant -- the recovered state equals the model's committed state at
 * some commit index p with acked <= p <= total. every acked commit was reported durable so it must
 * survive (p is at least acked), and a commit still in flight when the kill landed may or may not
 * have reached the log (p is at most total), so any prefix in that window is legal but nothing
 * outside it is. the check folds the recovered state into a 128-bit fingerprint and matches it
 * against the fingerprint of every prefix in the window, which also reads every entry back and so
 * catches corruption or a dangling value-log reference. the fork happens before any database opens,
 * so no engine thread or lock is inherited. */

#if defined(_WIN32)
int main(void)
{
    fprintf(stderr, "crash harness: not supported on this platform\n");
    return 0;
}
#else
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#define CRASH_KLEN_MAX         4
#define CRASH_VLEN_MAX         2048
#define CRASH_ALPHABET         6
#define CRASH_SPILL_VLEN       1500
#define CRASH_VALUE_TABLE      16
#define CRASH_MAX_OPS          2048
#define CRASH_WRITE_BUFFER     8192
#define CRASH_PATH_MAX         512
#define CRASH_MAX_KILL_ACKS    24
#define CRASH_CF               "c0"
#define CRASH_STANDALONE_ITERS 150
#define CRASH_STANDALONE_MAX   4096

#define CRASH_CHECK(cond, ...)                      \
    do                                              \
    {                                               \
        if (!(cond))                                \
        {                                           \
            fprintf(stderr, "CRASH ORACLE FAIL: "); \
            fprintf(stderr, __VA_ARGS__);           \
            fprintf(stderr, "\n");                  \
            fflush(stderr);                         \
            abort();                                \
        }                                           \
    } while (0)

typedef enum
{
    COP_PUT,
    COP_DELETE,
    COP_COMMIT
} crash_op_type_t;

typedef struct
{
    crash_op_type_t type;
    uint8_t key[CRASH_KLEN_MAX];
    size_t klen;
    uint8_t val[CRASH_VLEN_MAX];
    size_t vlen;
} crash_op_t;

typedef struct
{
    const uint8_t *d;
    size_t n;
    size_t pos;
} crash_reader_t;

static uint8_t crash_byte(crash_reader_t *r)
{
    return r->pos < r->n ? r->d[r->pos++] : 0;
}

/* decode the next operation; the value tag makes each put distinct so a stale survivor is caught,
 * and both the child (applying to the database) and the parent (replaying into the model) decode
 * the same stream identically. returns 0 when the input is exhausted */
static int crash_next_op(crash_reader_t *r, crash_op_t *op, uint64_t *tag)
{
    if (r->pos >= r->n) return 0;
    const uint8_t sel = crash_byte(r) % 4;
    op->type = sel <= 1 ? COP_PUT : (sel == 2 ? COP_DELETE : COP_COMMIT);
    if (op->type == COP_COMMIT) return 1;

    op->klen = (size_t)(crash_byte(r) % CRASH_KLEN_MAX) + 1;
    for (size_t i = 0; i < op->klen; i++)
        op->key[i] = (uint8_t)('a' + (crash_byte(r) % CRASH_ALPHABET));
    if (op->type == COP_PUT)
    {
        const uint8_t vs = crash_byte(r);
        op->vlen = (vs % CRASH_VALUE_TABLE == CRASH_VALUE_TABLE - 1)
                       ? CRASH_SPILL_VLEN
                       : (size_t)(vs % CRASH_VALUE_TABLE) + 1;
        const uint64_t t = (*tag)++;
        for (size_t i = 0; i < op->vlen; i++) op->val[i] = (uint8_t)(t + i);
    }
    return 1;
}

static tidesdb_config_t crash_config(char *path)
{
    tidesdb_config_t cfg = tidesdb_default_config();
    cfg.db_path = path;
    cfg.memtable_write_buffer_size = CRASH_WRITE_BUFFER;
    cfg.memtable_sync_mode = TDB_SYNC_FULL; /* a returned commit must be durable for the oracle */
    return cfg;
}

/* the child: apply the stream to the database and write the running committed count to the pipe
 * after each durable commit, then exit -- unless the parent kills it first */
static void crash_child(const uint8_t *data, size_t size, char *dir, int ackfd)
{
    tidesdb_t *db = NULL;
    tidesdb_config_t cfg = crash_config(dir);
    if (tidesdb_open(&cfg, &db) != TDB_SUCCESS) _exit(1);
    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    if (tidesdb_create_column_family(db, CRASH_CF, &cc) != TDB_SUCCESS) _exit(1);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, CRASH_CF);

    crash_reader_t r = {data, size, 0};
    crash_op_t op;
    uint64_t tag = 0;
    uint32_t commits = 0;
    tidesdb_txn_t *txn = NULL;
    int nops = 0;
    while (nops++ < CRASH_MAX_OPS && crash_next_op(&r, &op, &tag))
    {
        if (op.type == COP_COMMIT)
        {
            if (!txn) continue;
            if (tidesdb_txn_commit(txn) == TDB_SUCCESS)
            {
                commits++;
                (void)!write(ackfd, &commits, sizeof(commits)); /* ack a durable commit */
            }
            tidesdb_txn_free(txn);
            txn = NULL;
            continue;
        }
        if (!txn && tidesdb_txn_begin(db, &txn) != TDB_SUCCESS) continue;
        if (op.type == COP_PUT)
            (void)tidesdb_txn_put(txn, cf, op.key, op.klen, op.val, op.vlen, -1);
        else
            (void)tidesdb_txn_delete(txn, cf, op.key, op.klen);
    }
    if (txn)
    {
        (void)tidesdb_txn_rollback(txn);
        tidesdb_txn_free(txn);
    }
    (void)tidesdb_close(db);
    _exit(0);
}

/* a fingerprint of a full committed state, a 128-bit xxhash fold over every (klen, key, vlen, val)
 * in byte order; two distinct states collide only with negligible probability, so fingerprint
 * equality is an exact-state check that needs no per-prefix key storage */
typedef XXH128_hash_t crash_fp_t;

/* the initial capacity of the per-commit fingerprint array, doubled as it fills */
#define CRASH_FP_INIT_CAP   64

/* initial capacity of the materialized engine-scan array, doubled as it fills */
#define CRASH_SCAN_INIT_CAP 64

/* fold one length-prefixed field into the running fingerprint so a key and the value after it can
 * never alias across the boundary */
static void crash_fp_field(XXH3_state_t *st, size_t len, const uint8_t *p)
{
    uint8_t lb[sizeof(uint64_t)];
    const uint64_t n = (uint64_t)len;
    for (size_t i = 0; i < sizeof(lb); i++) lb[i] = (uint8_t)(n >> (8 * i));
    (void)XXH3_128bits_update(st, lb, sizeof(lb));
    if (len) (void)XXH3_128bits_update(st, p, len);
}

/* fingerprint the model's committed state; the scan is over committed data since no transaction is
 * open at a commit boundary */
static crash_fp_t crash_model_fp(const fuzz_model_t *m, XXH3_state_t *st)
{
    (void)XXH3_128bits_reset(st);
    fuzz_model_kv_t *kv = NULL;
    size_t kn = 0;
    if (fuzz_model_scan(m, CRASH_CF, &kv, &kn))
        for (size_t i = 0; i < kn; i++)
        {
            crash_fp_field(st, kv[i].klen, kv[i].key);
            crash_fp_field(st, kv[i].vlen, kv[i].val);
        }
    free(kv);
    return XXH3_128bits_digest(st);
}

/* append a fingerprint, growing the array as needed; a failure leaves the array a valid shorter
 * prefix */
static int crash_fp_push(crash_fp_t **a, size_t *n, size_t *cap, crash_fp_t fp)
{
    if (*n == *cap)
    {
        const size_t nc = *cap ? *cap * 2 : CRASH_FP_INIT_CAP;
        crash_fp_t *grown = realloc(*a, nc * sizeof(**a));
        if (!grown) return 0;
        *a = grown;
        *cap = nc;
    }
    (*a)[(*n)++] = fp;
    return 1;
}

/* replay the stream into the model and record the fingerprint after each commit; index 0 is the
 * empty state, index i the state after i commits, so out_total is the number of commits and the
 * array has out_total + 1 entries. the recovered state must equal one of these at index in [acked,
 * total] */
static crash_fp_t *crash_build_prefixes(const uint8_t *data, size_t size, size_t *out_total)
{
    *out_total = 0;
    XXH3_state_t *st = XXH3_createState();
    fuzz_model_t *m = fuzz_model_create();
    if (!st || !m || !fuzz_model_cf_create(m, CRASH_CF))
    {
        if (st) XXH3_freeState(st);
        fuzz_model_free(m);
        return NULL;
    }
    crash_fp_t *fps = NULL;
    size_t n = 0, cap = 0;
    if (!crash_fp_push(&fps, &n, &cap, crash_model_fp(m, st)))
    {
        XXH3_freeState(st);
        fuzz_model_free(m);
        return NULL;
    }
    crash_reader_t r = {data, size, 0};
    crash_op_t op;
    uint64_t tag = 0;
    int nops = 0;
    while (nops++ < CRASH_MAX_OPS && crash_next_op(&r, &op, &tag))
    {
        if (op.type == COP_COMMIT)
        {
            if (!fuzz_model_txn_open(m)) continue;
            fuzz_model_txn_commit(m);
            if (!crash_fp_push(&fps, &n, &cap, crash_model_fp(m, st))) break;
            continue;
        }
        if (!fuzz_model_txn_open(m)) fuzz_model_txn_begin(m);
        if (op.type == COP_PUT)
            (void)fuzz_model_put(m, CRASH_CF, op.key, op.klen, op.val, op.vlen, FUZZ_TTL_NONE);
        else
            (void)fuzz_model_delete(m, CRASH_CF, op.key, op.klen);
    }
    XXH3_freeState(st);
    fuzz_model_free(m);
    *out_total = n - 1;
    return fps;
}

/* fingerprint the reopened database; reading every entry back also proves each resolves without
 * corruption or a dangling value-log reference */
static crash_fp_t crash_engine_fp(tidesdb_t *db, tidesdb_column_family_t *cf)
{
    XXH3_state_t *st = XXH3_createState();
    CRASH_CHECK(st != NULL, "fingerprint state alloc");
    (void)XXH3_128bits_reset(st);
    tidesdb_txn_t *t = NULL;
    CRASH_CHECK(tidesdb_txn_begin(db, &t) == TDB_SUCCESS, "recovery read txn begin");
    tidesdb_iter_t *it = NULL;
    CRASH_CHECK(tidesdb_iter_new(t, cf, &it) == TDB_SUCCESS, "recovery iter");
    (void)tidesdb_iter_seek_to_first(it);
    while (tidesdb_iter_valid(it))
    {
        uint8_t *k = NULL, *v = NULL;
        size_t kl = 0, vl = 0;
        CRASH_CHECK(tidesdb_iter_key_value(it, &k, &kl, &v, &vl) == TDB_SUCCESS,
                    "recovered entry unreadable (corruption or dangling reference)");
        crash_fp_field(st, kl, k);
        crash_fp_field(st, vl, v);
        free(k);
        free(v);
        (void)tidesdb_iter_next(it);
    }
    tidesdb_iter_free(it);
    (void)tidesdb_txn_commit(t);
    tidesdb_txn_free(t);
    const crash_fp_t fp = XXH3_128bits_digest(st);
    XXH3_freeState(st);
    return fp;
}

/* replay the stream into the model up to commit_limit commits and return the committed scan; the
 * caller frees both the model (via the returned handle) and the array */
static fuzz_model_kv_t *crash_model_scan_at(const uint8_t *data, size_t size, size_t commit_limit,
                                            size_t *out_n, fuzz_model_t **out_model)
{
    *out_n = 0;
    *out_model = NULL;
    fuzz_model_t *m = fuzz_model_create();
    if (!m || !fuzz_model_cf_create(m, CRASH_CF))
    {
        fuzz_model_free(m);
        return NULL;
    }
    crash_reader_t r = {data, size, 0};
    crash_op_t op;
    uint64_t tag = 0;
    size_t commits = 0;
    int nops = 0;
    while (nops++ < CRASH_MAX_OPS && commits < commit_limit && crash_next_op(&r, &op, &tag))
    {
        if (op.type == COP_COMMIT)
        {
            if (!fuzz_model_txn_open(m)) continue;
            fuzz_model_txn_commit(m);
            commits++;
            continue;
        }
        if (!fuzz_model_txn_open(m)) fuzz_model_txn_begin(m);
        if (op.type == COP_PUT)
            (void)fuzz_model_put(m, CRASH_CF, op.key, op.klen, op.val, op.vlen, FUZZ_TTL_NONE);
        else
            (void)fuzz_model_delete(m, CRASH_CF, op.key, op.klen);
    }
    fuzz_model_kv_t *kv = NULL;
    (void)fuzz_model_scan(m, CRASH_CF, &kv, out_n);
    *out_model = m;
    return kv;
}

/* one recovered (key, value) pair the engine scan materialized, owning its bytes */
typedef struct
{
    uint8_t *key;
    size_t klen;
    uint8_t *val;
    size_t vlen;
} crash_kv_t;

/* materialize the recovered cf scan into an owned, ascending array; caller frees each key/val and
 * arr */
static crash_kv_t *crash_engine_scan(tidesdb_t *db, tidesdb_column_family_t *cf, size_t *out_n)
{
    *out_n = 0;
    crash_kv_t *arr = NULL;
    size_t n = 0, cap = 0;
    tidesdb_txn_t *t = NULL;
    tidesdb_iter_t *it = NULL;
    (void)tidesdb_txn_begin(db, &t);
    (void)tidesdb_iter_new(t, cf, &it);
    (void)tidesdb_iter_seek_to_first(it);
    while (tidesdb_iter_valid(it))
    {
        uint8_t *k = NULL, *v = NULL;
        size_t kl = 0, vl = 0;
        if (tidesdb_iter_key_value(it, &k, &kl, &v, &vl) != TDB_SUCCESS) break;
        if (n == cap)
        {
            const size_t nc = cap ? cap * 2 : CRASH_SCAN_INIT_CAP;
            crash_kv_t *g = realloc(arr, nc * sizeof(*g));
            if (!g)
            {
                free(k);
                free(v);
                break;
            }
            arr = g;
            cap = nc;
        }
        arr[n].key = k;
        arr[n].klen = kl;
        arr[n].val = v;
        arr[n].vlen = vl;
        n++;
        (void)tidesdb_iter_next(it);
    }
    tidesdb_iter_free(it);
    (void)tidesdb_txn_commit(t);
    tidesdb_txn_free(t);
    *out_n = n;
    return arr;
}

/* number of keys that differ (present on one side only, or same key with a different value) between
 * an ascending engine scan and an ascending model scan */
static size_t crash_scan_diff(const crash_kv_t *ek, size_t en, const fuzz_model_kv_t *mk, size_t mn)
{
    size_t i = 0, j = 0, diff = 0;
    while (i < en && j < mn)
    {
        const int c = fuzz_key_cmp(ek[i].key, ek[i].klen, mk[j].key, mk[j].klen);
        if (c < 0)
        {
            diff++;
            i++;
        }
        else if (c > 0)
        {
            diff++;
            j++;
        }
        else
        {
            if (!fuzz_value_eq(ek[i].val, ek[i].vlen, mk[j].val, mk[j].vlen)) diff++;
            i++;
            j++;
        }
    }
    return diff + (en - i) + (mn - j);
}

/* trace and print every committed put/delete of one key across the stream, then its final committed
 * state, so a divergent key can be read against what the stream actually committed */
static void crash_trace_key(const uint8_t *data, size_t size, const uint8_t *key, size_t klen)
{
    crash_reader_t r = {data, size, 0};
    crash_op_t op;
    uint64_t tag = 0;
    int nops = 0, has = 0, del = 0, last = -1;
    size_t commits = 0;
    fprintf(stderr, "  trace '%.*s':", (int)klen, key);
    while (nops++ < CRASH_MAX_OPS && crash_next_op(&r, &op, &tag))
    {
        if (op.type == COP_COMMIT)
        {
            if (has)
            {
                fprintf(stderr, " c%zu:%s", commits, del ? "DEL" : "PUT");
                last = del ? 0 : 1;
            }
            commits++;
            has = 0;
            del = 0;
            continue;
        }
        if (op.klen == klen && memcmp(op.key, key, klen) == 0)
        {
            has = 1;
            del = (op.type == COP_DELETE);
        }
    }
    fprintf(stderr, " => final %s\n", last < 0 ? "NEVER" : (last ? "PRESENT" : "ABSENT"));
}

/* find the committed prefix nearest the recovered state and print how they differ, keyed by the
 * actual committed history so a lost, phantom, or wrong-version key stands out, then abort */
static void crash_report_divergence(const uint8_t *data, size_t size, tidesdb_t *db,
                                    tidesdb_column_family_t *cf, uint32_t acked, size_t total)
{
    size_t en = 0;
    crash_kv_t *ek = crash_engine_scan(db, cf, &en);

    size_t best_p = acked, best_diff = (size_t)-1;
    for (size_t p = acked; p <= total; p++)
    {
        size_t mn = 0;
        fuzz_model_t *m = NULL;
        fuzz_model_kv_t *mk = crash_model_scan_at(data, size, p, &mn, &m);
        const size_t d = crash_scan_diff(ek, en, mk, mn);
        free(mk);
        fuzz_model_free(m);
        if (d < best_diff)
        {
            best_diff = d;
            best_p = p;
        }
    }
    fprintf(stderr, "DIVERGENCE acked=%u total=%zu engine_keys=%zu nearest_prefix=%zu diffs=%zu\n",
            acked, total, en, best_p, best_diff);

    size_t mn = 0;
    fuzz_model_t *m = NULL;
    fuzz_model_kv_t *mk = crash_model_scan_at(data, size, best_p, &mn, &m);
    size_t i = 0, j = 0, reported = 0;
    while ((i < en || j < mn) && reported < CRASH_MAX_KILL_ACKS)
    {
        const int c = (i < en && j < mn)
                          ? fuzz_key_cmp(ek[i].key, ek[i].klen, mk[j].key, mk[j].klen)
                          : (i < en ? -1 : 1);
        if (c < 0)
        {
            fprintf(stderr, "  ENGINE-ONLY '%.*s' vlen=%zu\n", (int)ek[i].klen, ek[i].key,
                    ek[i].vlen);
            crash_trace_key(data, size, ek[i].key, ek[i].klen);
            reported++;
            i++;
        }
        else if (c > 0)
        {
            fprintf(stderr, "  MODEL-ONLY '%.*s' vlen=%zu\n", (int)mk[j].klen, mk[j].key,
                    mk[j].vlen);
            crash_trace_key(data, size, mk[j].key, mk[j].klen);
            reported++;
            j++;
        }
        else
        {
            if (!fuzz_value_eq(ek[i].val, ek[i].vlen, mk[j].val, mk[j].vlen))
            {
                fprintf(stderr, "  VALUE-DIFF '%.*s' engine_vlen=%zu model_vlen=%zu\n",
                        (int)ek[i].klen, ek[i].key, ek[i].vlen, mk[j].vlen);
                reported++;
            }
            i++;
            j++;
        }
    }
    free(mk);
    fuzz_model_free(m);
    for (size_t x = 0; x < en; x++)
    {
        free(ek[x].key);
        free(ek[x].val);
    }
    free(ek);
    CRASH_CHECK(0, "recovered state matches no committed prefix (see divergence above)");
}

/* the recovered state must match the model at some commit index in [acked, total]: no acked commit
 * may be lost (durability) and nothing past the last durable commit may appear (no phantom or torn
 * data) */
static void crash_check_recovered(const uint8_t *data, size_t size, tidesdb_t *db,
                                  tidesdb_column_family_t *cf, const crash_fp_t *fps, size_t total,
                                  uint32_t acked, crash_fp_t eng)
{
    size_t lo = acked;
    if (lo > total)
        lo = total; /* the child cannot ack more commits than the full stream contains */
    for (size_t p = lo; p <= total; p++)
        if (fps[p].low64 == eng.low64 && fps[p].high64 == eng.high64) return;
    crash_report_divergence(data, size, db, cf, acked, total);
}

/* when TIDESDB_FUZZ_DUMP is set, write the current input to last_input.bin so an aborting scenario
 * is reproducible by replaying that file */
static void crash_dump_input(const char *base, const uint8_t *data, size_t size)
{
    if (!getenv("TIDESDB_FUZZ_DUMP")) return;
    char path[CRASH_PATH_MAX];
    snprintf(path, sizeof(path), "%s%slast_input.bin", base ? base : ".", PATH_SEPARATOR);
    FILE *f = fopen(path, "wb");
    if (!f) return;
    if (size) (void)!fwrite(data, 1, size, f);
    fclose(f);
}

/* run one crash scenario: fork, drive the child, kill it, reopen, and check the recovery invariant
 */
static void crash_scenario(const uint8_t *data, size_t size)
{
    const char *base = getenv("TIDESDB_FUZZ_DIR");
    char dir[CRASH_PATH_MAX];
    snprintf(dir, sizeof(dir), "%s%scrashdb", base ? base : ".", PATH_SEPARATOR);
    (void)remove_directory(dir);
    crash_dump_input(base, data, size);

    const uint32_t kill_after = size > 0 ? (uint32_t)(data[size - 1] % CRASH_MAX_KILL_ACKS) : 0;

    int fds[2];
    if (pipe(fds) != 0) return;
    const pid_t pid = fork();
    if (pid < 0)
    {
        close(fds[0]);
        close(fds[1]);
        return;
    }
    if (pid == 0)
    {
        close(fds[0]);
        crash_child(data, size, dir, fds[1]); /* never returns */
    }

    close(fds[1]);
    uint32_t acked = 0, val = 0;
    while (read(fds[0], &val, sizeof(val)) == (ssize_t)sizeof(val))
    {
        acked = val;
        if (kill_after > 0 && acked >= kill_after)
        {
            kill(pid, SIGKILL);
            break;
        }
    }
    close(fds[0]);
    int status = 0;
    (void)waitpid(pid, &status, 0);

    tidesdb_t *db = NULL;
    tidesdb_config_t cfg = crash_config(dir);
    CRASH_CHECK(tidesdb_open(&cfg, &db) == TDB_SUCCESS, "reopen after crash failed");
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, CRASH_CF);
    if (!cf)
    {
        CRASH_CHECK(acked == 0, "cf gone though %u commits were acked", acked);
        (void)tidesdb_close(db);
        (void)remove_directory(dir);
        return;
    }

    size_t total = 0;
    crash_fp_t *fps = crash_build_prefixes(data, size, &total);
    if (fps)
    {
        const crash_fp_t eng = crash_engine_fp(db, cf);
        crash_check_recovered(data, size, db, cf, fps, total, acked, eng);
        free(fps);
    }

    (void)tidesdb_close(db);
    (void)remove_directory(dir);
}

/* a deterministic generator so a seed reproduces the same crash inputs for the ci run */
static uint64_t crash_rng(uint64_t *state)
{
    uint64_t x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

static int crash_replay_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return 1;
    fseek(f, 0, SEEK_END);
    const long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc(n > 0 ? (size_t)n : 1);
    if (!buf)
    {
        fclose(f);
        return 1;
    }
    const size_t got = n > 0 ? fread(buf, 1, (size_t)n, f) : 0;
    fclose(f);
    fprintf(stderr, "crash replay %s (%zu bytes)\n", path, got);
    crash_scenario(buf, got);
    free(buf);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 1)
    {
        int rc = 0;
        for (int i = 1; i < argc; i++) rc |= crash_replay_file(argv[i]);
        return rc;
    }

    const char *iters_env = getenv("TIDESDB_FUZZ_ITERS");
    const long iters = iters_env ? strtol(iters_env, NULL, 10) : CRASH_STANDALONE_ITERS;
    const char *seed_env = getenv("TIDESDB_FUZZ_SEED");
    uint64_t state = seed_env ? (uint64_t)strtoull(seed_env, NULL, 10) : 0x9e3779b97f4a7c15ULL;
    if (state == 0) state = 0x9e3779b97f4a7c15ULL;

    uint8_t *buf = malloc(CRASH_STANDALONE_MAX);
    if (!buf) return 1;
    for (long it = 0; it < iters; it++)
    {
        const size_t len = (size_t)(crash_rng(&state) % CRASH_STANDALONE_MAX) + 1;
        for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)crash_rng(&state);
        crash_scenario(buf, len);
    }
    free(buf);
    fprintf(stderr, "crash fuzz: %ld iterations passed\n", iters);
    return 0;
}
#endif /* _WIN32 */
