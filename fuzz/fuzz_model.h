/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_FUZZ_MODEL_H__
#define __TIDESDB_FUZZ_MODEL_H__

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

/**
 * fuzz_value_eq
 * compare two stored values, either of which may be empty.
 *
 * an empty value is a value the engine stores, and it hands one back as a NULL buffer with a zero
 * size rather than as a zero-length allocation. passing that to memcmp is undefined even for a
 * count of zero, so the length settles it before any pointer is read
 * @param a first value, which may be NULL when an is zero
 * @param an length of a
 * @param b second value, which may be NULL when bn is zero
 * @param bn length of b
 * @return 1 when the two are the same value
 */
static inline int fuzz_value_eq(const uint8_t *a, size_t an, const uint8_t *b, size_t bn)
{
    if (an != bn) return 0;
    return an == 0 || memcmp(a, b, an) == 0;
}

/* the reference model is an obviously-correct in-memory oracle for a subset of the tidesdb
 * contract: a set of column families, each an ordered byte-wise key -> versioned entry map, plus a
 * single open transaction whose buffered writes overlay the committed state with
 * read-your-own-writes.
 *
 * the model carries a sequence clock because write order is not the same as apply order. a
 * transaction takes its sequence when it commits, and a two-phase transaction takes one when phase
 * two decides it rather than when it prepared, so a batch is ordered where it was decided. the
 * model still tracks sequences because clone copies them and because an apply at an older sequence
 * must be ignored rather than overwrite: every committed key holds the sequence that wrote it, and
 * a delete leaves a tombstone rather than removing the key so that sequence stays available.
 *
 * the fuzzer drives one transaction at a time apart from an in-doubt prepared one, so the model
 * needs no snapshots or read sets and every isolation level reads the same committed state. flush,
 * compaction, and value-log reclaim are transparent to results, so the model never models them
 * -- the harness asserts the database still matches the model after each of them.
 *
 * an entry carries the absolute deadline its put fixed, and a version past it reads as absent
 * without leaving the map, mirroring the engine's evaluate-on-read expiry. the harness only writes
 * lifetimes that are unambiguous for a whole run, because the engine's expiry compares against a
 * one-second wall clock and a lifetime expiring mid-run would put the model and the database on
 * opposite sides of that boundary, making the oracle rather than the engine the thing that fails */

/* byte-wise key order matching the engine: shared prefix compares by memcmp, then the shorter key
 * is smaller. returns <0, 0, or >0 */
int fuzz_key_cmp(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen);

typedef struct fuzz_model fuzz_model_t;

/**
 * fuzz_model_create
 * create an empty model with no column families and no open transaction
 * @return the model, or NULL on allocation failure
 */
fuzz_model_t *fuzz_model_create(void);

/**
 * fuzz_model_free
 * free the model and every column family, key, and value it holds; safe on NULL
 * @param m the model
 */
void fuzz_model_free(fuzz_model_t *m);

/**
 * fuzz_model_cf_exists / fuzz_model_cf_create / fuzz_model_cf_drop / fuzz_model_cf_rename /
 * fuzz_model_cf_clone
 * mirror the engine's column family lifecycle; create rejects a duplicate, drop/rename/clone act on
 * an existing family, clone deep-copies the source map under the new name
 * @return 1 on success (create/clone: the name was free; drop/rename: the family existed), 0
 * otherwise
 */
int fuzz_model_cf_exists(const fuzz_model_t *m, const char *name);
int fuzz_model_cf_create(fuzz_model_t *m, const char *name);
int fuzz_model_cf_drop(fuzz_model_t *m, const char *name);
int fuzz_model_cf_rename(fuzz_model_t *m, const char *old_name, const char *new_name);
int fuzz_model_cf_clone(fuzz_model_t *m, const char *src, const char *dst);

/**
 * fuzz_model_cf_count / fuzz_model_cf_name_at
 * enumerate the model's column families, so a caller can compare the whole set against the database
 * in both directions rather than only checking that every database family is known
 * @param m the model
 * @param index a position in [0, fuzz_model_cf_count)
 * @return the count, and the name at index or NULL when index is out of range
 */
int fuzz_model_cf_count(const fuzz_model_t *m);
const char *fuzz_model_cf_name_at(const fuzz_model_t *m, int index);

/**
 * fuzz_model_txn_begin / fuzz_model_txn_commit / fuzz_model_txn_rollback
 * open, apply, or discard the single transaction; begin is a no-op if one is already open, commit
 * folds the buffered writes into the committed maps, rollback drops them
 */
void fuzz_model_txn_begin(fuzz_model_t *m);
void fuzz_model_txn_commit(fuzz_model_t *m);
void fuzz_model_txn_rollback(fuzz_model_t *m);
int fuzz_model_txn_open(const fuzz_model_t *m);

/**
 * fuzz_model_txn_prepare / fuzz_model_commit_prepared / fuzz_model_rollback_prepared /
 * fuzz_model_prepared_open
 * mirror two-phase commit: prepare holds the open transaction's buffer aside, still invisible and
 * still uncommitted, and phase two either applies it at a sequence drawn when it decides or
 * discards it. drawing the sequence at phase two rather than at prepare is what puts a decided
 * batch above everything that committed while it was in doubt, matching the engine. a read-only
 * transaction prepares to nothing and finishes outright, exactly as the engine resolves it
 * @return 1 when the model moved, 0 when there was nothing in that state to move
 */
int fuzz_model_txn_prepare(fuzz_model_t *m);
int fuzz_model_commit_prepared(fuzz_model_t *m);
int fuzz_model_rollback_prepared(fuzz_model_t *m);
int fuzz_model_prepared_open(const fuzz_model_t *m);

/**
 * fuzz_model_txn_hits_prepared
 * whether the open transaction buffers something the prepared batch's reservations must refuse,
 * which is what decides whether the engine's first-committer-wins check has to fail its commit
 *
 * the engine claims an interval against the other intervals only, and checks a point write against
 * both the intervals and the point reservations, an interval having no one key to hash. so a point
 * meeting either kind is refused and an interval meeting another interval is refused, while an
 * interval meeting a held point is not -- and this deliberately does not answer symmetrically
 * @param m the model
 * @return 1 when the open transaction must lose to the prepared batch, 0 otherwise
 */
int fuzz_model_txn_hits_prepared(const fuzz_model_t *m);

/**
 * fuzz_model_savepoint / fuzz_model_rollback_to / fuzz_model_release
 * mark, rewind to, or forget a named savepoint in the open transaction's buffer; names are matched
 * by string, the newest match wins
 * @return 1 on success, 0 when no transaction is open or the name is unknown (rollback_to/release)
 */
int fuzz_model_savepoint(fuzz_model_t *m, const char *name);
int fuzz_model_rollback_to(fuzz_model_t *m, const char *name);
int fuzz_model_release(fuzz_model_t *m, const char *name);

/**
 * fuzz_model_put / fuzz_model_delete
 * buffer a write in the open transaction; a caller opens one first
 * @param ttl_seconds the entry's lifetime in seconds from now, zero or negative for no expiry,
 * converted to an absolute deadline here exactly as the engine converts it at the put so a replay
 * cannot restart the clock
 * @return 1 on success, 0 when no transaction is open or on allocation failure
 */
int fuzz_model_put(fuzz_model_t *m, const char *cf, const uint8_t *key, size_t klen,
                   const uint8_t *val, size_t vlen, time_t ttl_seconds);

/* the lifetime a write carries when it must never expire, spelled once for every fuzzer that writes
 * without exercising expiry */
#define FUZZ_TTL_NONE 0
int fuzz_model_delete(fuzz_model_t *m, const char *cf, const uint8_t *key, size_t klen);

/**
 * fuzz_model_delete_range / fuzz_model_delete_prefix
 * buffer an interval tombstone covering lo (inclusive) to hi (exclusive), or every key under a
 * prefix, which is the interval from the prefix to its successor
 *
 * an interval hides the keys committed below the batch's sequence and the keys buffered before it
 * in the same transaction, and a write buffered after it survives it. that is why the buffer is an
 * ordered log rather than a map: position in it is what decides which of the two is newer
 * @param m the model
 * @param cf the column family name
 * @param lo inclusive lower bound, never empty
 * @param lolen size of lo in bytes
 * @param hi exclusive upper bound, or NULL with hilen zero to run to the end of the family
 * @param hilen size of hi in bytes, zero for the end of the family
 * @param prefix the prefix to delete under, never empty
 * @param plen size of prefix in bytes
 * @return 1 on success, 0 when no transaction is open or on allocation failure
 */
int fuzz_model_delete_range(fuzz_model_t *m, const char *cf, const uint8_t *lo, size_t lolen,
                            const uint8_t *hi, size_t hilen);
int fuzz_model_delete_prefix(fuzz_model_t *m, const char *cf, const uint8_t *prefix, size_t plen);

/**
 * fuzz_model_get
 * read a key as the open transaction (buffer over committed) sees it, or as committed when none is
 * open
 * @param m the model
 * @param cf the column family name
 * @param key the key bytes
 * @param klen the key length
 * @param out_val receives a pointer into the model's storage, valid until the next model mutation
 * @param out_vlen receives the value length
 * @return 1 when the key is present, 0 when absent or the cf is unknown
 */
int fuzz_model_get(const fuzz_model_t *m, const char *cf, const uint8_t *key, size_t klen,
                   const uint8_t **out_val, size_t *out_vlen);

/**
 * fuzz_model_get_committed
 * read a key as the committed state alone, ignoring any open transaction's buffered writes, so a
 * caller can tell a read-your-writes result apart from a committed one
 * @param m the model
 * @param cf the column family name
 * @param key the key bytes
 * @param klen the key length
 * @param out_val receives a pointer into the model's storage, valid until the next model mutation
 * @param out_vlen receives the value length
 * @return 1 when the key is committed present, 0 when absent or the cf is unknown
 */
int fuzz_model_get_committed(const fuzz_model_t *m, const char *cf, const uint8_t *key, size_t klen,
                             const uint8_t **out_val, size_t *out_vlen);

/**
 * fuzz_model_kv_t
 * one visible key/value pair produced by a scan, pointing into the model's storage
 */
typedef struct
{
    const uint8_t *key;
    size_t klen;
    const uint8_t *val;
    size_t vlen;
} fuzz_model_kv_t;

/**
 * fuzz_model_scan
 * materialize the visible key/value pairs of a column family in ascending byte order, as the open
 * transaction (buffer over committed) sees them, or as committed when none is open
 * @param m the model
 * @param cf the column family name
 * @param out receives a newly allocated array the caller frees, or NULL when the set is empty
 * @param out_count receives the number of pairs
 * @return 1 on success (including an empty set), 0 when the cf is unknown or on allocation failure
 */
int fuzz_model_scan(const fuzz_model_t *m, const char *cf, fuzz_model_kv_t **out,
                    size_t *out_count);

#endif /* __TIDESDB_FUZZ_MODEL_H__ */
