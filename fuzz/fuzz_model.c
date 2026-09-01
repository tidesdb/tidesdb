/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "fuzz_model.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* the longest column-family or savepoint name the model keeps, matching the fuzzer's bounded names
 */
#define FM_NAME_MAX 64

/* the deadline of an entry that never expires, matching the engine's TDB_TTL_NONE */
#define FM_TTL_NONE (-1)

/* the largest byte a key can hold, which is the one a prefix cannot be advanced past */
#define FM_KEY_BYTE_MAX 0xff

/* the engine converts a caller's lifetime to an absolute deadline once, at the put, so a replay
 * cannot restart the clock. the model converts the same way and at the same moment, which is what
 * lets the two agree on visibility without the model knowing anything about the write path */
static int64_t fm_ttl_deadline(time_t ttl_seconds)
{
    if (ttl_seconds <= 0) return FM_TTL_NONE;

    const int64_t now = (int64_t)time(NULL);
    /* a lifetime long enough to overflow the deadline is one the caller means as forever */
    if (ttl_seconds > INT64_MAX - now) return FM_TTL_NONE;
    return now + (int64_t)ttl_seconds;
}

/* whether an entry is still visible, applying the engine's rule that a deadline at or before the
 * current second has passed */
static int fm_entry_live(int64_t deadline)
{
    return !(deadline > 0 && deadline <= (int64_t)time(NULL));
}

int fuzz_key_cmp(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen)
{
    const size_t m = alen < blen ? alen : blen;
    const int c = m ? memcmp(a, b, m) : 0;
    if (c != 0) return c;
    return alen < blen ? -1 : (alen > blen ? 1 : 0);
}

/* one committed key and the version that currently holds it, owning its bytes. seq is the sequence
 * of the write that produced this version, and tombstone marks a delete, which stays in the map so
 * an apply at an older sequence still resolves against it. deadline is the absolute expiry the put
 * fixed, so a version that outlives it reads as absent without being removed */
typedef struct
{
    uint8_t *key;
    size_t klen;
    uint8_t *val;
    size_t vlen;
    uint64_t seq;
    int tombstone;
    int64_t deadline;
} fm_entry_t;

/* a committed column family: its name, the identity buffered ops refer to it by, and a byte-sorted
 * array of entries. the id is what an op records, because a name is not a stable identity -- rename
 * and drop free a name for another family to take, and an op holding the name would then follow it
 * to whichever family holds it at commit rather than the one it was written against */
typedef struct
{
    uint64_t id;
    char name[FM_NAME_MAX];
    fm_entry_t *entries;
    size_t count;
    size_t cap;
} fm_cf_t;

/* what a buffered entry does: write a value, tombstone one key, or tombstone a half-open interval
 */
typedef enum
{
    FM_OP_PUT,
    FM_OP_DELETE,
    FM_OP_RANGE_DELETE
} fm_op_kind_t;

/* one buffered entry in the open transaction, owning its bytes; a delete carries no value and no
 * deadline. an interval delete carries its lower bound in key and its exclusive upper bound in hi,
 * where a NULL hi runs to the end of the family */
typedef struct
{
    uint64_t cf_id;
    fm_op_kind_t kind;
    uint8_t *key;
    size_t klen;
    uint8_t *hi;
    size_t hilen;
    uint8_t *val;
    size_t vlen;
    int64_t deadline;
} fm_op_t;

/* a savepoint: a name and the buffer length when it was marked */
typedef struct
{
    char name[FM_NAME_MAX];
    size_t buf_len;
} fm_sp_t;

struct fuzz_model
{
    fm_cf_t *cfs;
    size_t cf_count;
    size_t cf_cap;

    /* the next family identity to hand out. it only ever moves forward, so a dropped family's id is
     * never given to another one, the way the engine does not reuse a cf id either */
    uint64_t next_cf_id;

    /* the sequence clock, drawn at commit and at prepare in the same order the engine draws its
     * own, so the two agree on which of any two writes is newer even though the values differ */
    uint64_t clock;

    int txn_open;
    int txn_prepared; /* pbuf below is durably prepared and awaiting a phase-two decision */
    fm_op_t *pbuf;    /* the prepared batch, held apart so a later transaction cannot disturb it */
    size_t pbuf_count;
    size_t pbuf_cap;
    fm_op_t *buf;
    size_t buf_count;
    size_t buf_cap;
    fm_sp_t *sps;
    size_t sp_count;
    size_t sp_cap;
};

/* duplicate a byte buffer; a zero-length buffer yields a one-byte allocation so the pointer is
 * never NULL and never aliases */
static uint8_t *fm_dup(const uint8_t *src, size_t len)
{
    uint8_t *out = malloc(len ? len : 1);
    if (out && len) memcpy(out, src, len);
    return out;
}

fuzz_model_t *fuzz_model_create(void)
{
    return calloc(1, sizeof(fuzz_model_t));
}

static void fm_cf_clear(fm_cf_t *cf)
{
    for (size_t i = 0; i < cf->count; i++)
    {
        free(cf->entries[i].key);
        free(cf->entries[i].val);
    }
    free(cf->entries);
    cf->entries = NULL;
    cf->count = 0;
    cf->cap = 0;
}

static void fm_buf_clear(fuzz_model_t *m)
{
    for (size_t i = 0; i < m->buf_count; i++)
    {
        free(m->buf[i].key);
        free(m->buf[i].hi);
        free(m->buf[i].val);
    }
    m->buf_count = 0;
    m->sp_count = 0;
}

void fuzz_model_free(fuzz_model_t *m)
{
    if (!m) return;
    for (size_t i = 0; i < m->cf_count; i++) fm_cf_clear(&m->cfs[i]);
    free(m->cfs);
    fm_buf_clear(m);
    free(m->buf);
    /* an undecided prepared batch owns its own storage, released here rather than through the
     * phase-two helpers below, which are defined further down the file */
    for (size_t i = 0; i < m->pbuf_count; i++)
    {
        free(m->pbuf[i].key);
        free(m->pbuf[i].hi);
        free(m->pbuf[i].val);
    }
    free(m->pbuf);
    free(m->sps);
    free(m);
}

static fm_cf_t *fm_cf_find(const fuzz_model_t *m, const char *name)
{
    for (size_t i = 0; i < m->cf_count; i++)
        if (strcmp(m->cfs[i].name, name) == 0) return &m->cfs[i];
    return NULL;
}

/* the family an op was written against, or NULL when it has since been dropped. an id of zero names
 * no family, which is what an op buffered against a family that did not exist carries */
static fm_cf_t *fm_cf_find_by_id(const fuzz_model_t *m, uint64_t id)
{
    if (id == 0) return NULL;
    for (size_t i = 0; i < m->cf_count; i++)
        if (m->cfs[i].id == id) return &m->cfs[i];
    return NULL;
}

int fuzz_model_cf_exists(const fuzz_model_t *m, const char *name)
{
    return fm_cf_find(m, name) != NULL;
}

int fuzz_model_cf_create(fuzz_model_t *m, const char *name)
{
    if (fm_cf_find(m, name)) return 0;
    if (m->cf_count == m->cf_cap)
    {
        const size_t nc = m->cf_cap ? m->cf_cap * 2 : 4;
        fm_cf_t *grown = realloc(m->cfs, nc * sizeof(*grown));
        if (!grown) return 0;
        m->cfs = grown;
        m->cf_cap = nc;
    }
    fm_cf_t *cf = &m->cfs[m->cf_count++];
    memset(cf, 0, sizeof(*cf));
    cf->id = ++m->next_cf_id;
    snprintf(cf->name, sizeof(cf->name), "%s", name);
    return 1;
}

int fuzz_model_cf_drop(fuzz_model_t *m, const char *name)
{
    for (size_t i = 0; i < m->cf_count; i++)
        if (strcmp(m->cfs[i].name, name) == 0)
        {
            fm_cf_clear(&m->cfs[i]);
            memmove(&m->cfs[i], &m->cfs[i + 1], (m->cf_count - i - 1) * sizeof(*m->cfs));
            m->cf_count--;
            return 1;
        }
    return 0;
}

int fuzz_model_cf_rename(fuzz_model_t *m, const char *old_name, const char *new_name)
{
    if (fm_cf_find(m, new_name)) return 0;
    fm_cf_t *cf = fm_cf_find(m, old_name);
    if (!cf) return 0;
    snprintf(cf->name, sizeof(cf->name), "%s", new_name);
    return 1;
}

int fuzz_model_cf_clone(fuzz_model_t *m, const char *src, const char *dst)
{
    if (!fm_cf_find(m, src) || fm_cf_find(m, dst)) return 0;
    if (!fuzz_model_cf_create(m, dst)) return 0;
    /* create may have grown (reallocated) the cf array, so re-find both after it */
    const fm_cf_t *s = fm_cf_find(m, src);
    fm_cf_t *d = fm_cf_find(m, dst);
    if (!s || !d) return 0;
    for (size_t i = 0; i < s->count; i++)
    {
        uint8_t *k = fm_dup(s->entries[i].key, s->entries[i].klen);
        uint8_t *v = fm_dup(s->entries[i].val, s->entries[i].vlen);
        if (!k || !v)
        {
            free(k);
            free(v);
            return 0;
        }
        if (d->count == d->cap)
        {
            const size_t nc = d->cap ? d->cap * 2 : 8;
            fm_entry_t *grown = realloc(d->entries, nc * sizeof(*grown));
            if (!grown)
            {
                free(k);
                free(v);
                return 0;
            }
            d->entries = grown;
            d->cap = nc;
        }
        d->entries[d->count].key = k;
        d->entries[d->count].klen = s->entries[i].klen;
        d->entries[d->count].val = v;
        d->entries[d->count].vlen = s->entries[i].vlen;
        d->entries[d->count].seq = s->entries[i].seq;
        d->entries[d->count].tombstone = s->entries[i].tombstone;
        d->entries[d->count].deadline = s->entries[i].deadline;
        d->count++;
    }
    return 1;
}

/* binary search for key in a committed cf; returns the index when found, else the negative
 * insertion point encoded as -(pos + 1) */
static long fm_cf_search(const fm_cf_t *cf, const uint8_t *key, size_t klen)
{
    long lo = 0, hi = (long)cf->count - 1;
    while (lo <= hi)
    {
        const long mid = lo + (hi - lo) / 2;
        const int c = fuzz_key_cmp(cf->entries[mid].key, cf->entries[mid].klen, key, klen);
        if (c == 0) return mid;
        if (c < 0)
            lo = mid + 1;
        else
            hi = mid - 1;
    }
    return -(lo + 1);
}

/* apply one write at seq to a byte-sorted cf, taking it only when it is newer than the version the
 * key already holds; a delete lands as a tombstone so the sequence it carries stays available to
 * order a later apply. returns 0 only on allocation failure, since an ignored older write succeeded
 */
static int fm_cf_apply(fm_cf_t *cf, const uint8_t *key, size_t klen, const uint8_t *val,
                       size_t vlen, int is_delete, uint64_t seq, int64_t deadline)
{
    const long found = fm_cf_search(cf, key, klen);
    if (found >= 0)
    {
        /* strictly older loses. an equal sequence is another write of the same batch, applied in
         * order, so the later one wins exactly as the engine's deduplicated write set resolves it
         */
        if (seq < cf->entries[found].seq) return 1;
        uint8_t *nv = is_delete ? NULL : fm_dup(val, vlen);
        if (!is_delete && !nv) return 0;
        free(cf->entries[found].val);
        cf->entries[found].val = nv;
        cf->entries[found].vlen = is_delete ? 0 : vlen;
        cf->entries[found].seq = seq;
        cf->entries[found].tombstone = is_delete;
        cf->entries[found].deadline = deadline;
        return 1;
    }

    const size_t pos = (size_t)(-found - 1);
    uint8_t *nk = fm_dup(key, klen);
    uint8_t *nv = is_delete ? NULL : fm_dup(val, vlen);
    if (!nk || (!is_delete && !nv))
    {
        free(nk);
        free(nv);
        return 0;
    }
    if (cf->count == cf->cap)
    {
        const size_t nc = cf->cap ? cf->cap * 2 : 8;
        fm_entry_t *grown = realloc(cf->entries, nc * sizeof(*grown));
        if (!grown)
        {
            free(nk);
            free(nv);
            return 0;
        }
        cf->entries = grown;
        cf->cap = nc;
    }
    memmove(&cf->entries[pos + 1], &cf->entries[pos], (cf->count - pos) * sizeof(*cf->entries));
    cf->entries[pos].key = nk;
    cf->entries[pos].klen = klen;
    cf->entries[pos].val = nv;
    cf->entries[pos].vlen = is_delete ? 0 : vlen;
    cf->entries[pos].seq = seq;
    cf->entries[pos].tombstone = is_delete;
    cf->entries[pos].deadline = deadline;
    cf->count++;
    return 1;
}

/* whether an interval delete covers a key, applying the engine's half-open rule: at or above the
 * lower bound, and below the upper one unless the interval is open above */
static int fm_op_covers(const fm_op_t *op, const uint8_t *key, const size_t klen)
{
    if (fuzz_key_cmp(op->key, op->klen, key, klen) > 0) return 0;
    if (op->hilen == 0) return 1;
    return fuzz_key_cmp(key, klen, op->hi, op->hilen) < 0;
}

/* tombstone every committed key an interval covers, at the sequence the batch landed at. a key
 * written at a later sequence outlives the interval, exactly as a point delete leaves it alone.
 * every key touched is already in the map, so each write lands in place and the sorted array is
 * never resized under the walk */
static void fm_apply_range(fm_cf_t *cf, const fm_op_t *op, const uint64_t seq)
{
    for (size_t i = 0; i < cf->count; i++)
    {
        if (fuzz_key_cmp(cf->entries[i].key, cf->entries[i].klen, op->key, op->klen) < 0) continue;
        if (op->hilen &&
            fuzz_key_cmp(cf->entries[i].key, cf->entries[i].klen, op->hi, op->hilen) >= 0)
            break; /* sorted, so the first key at or above the upper bound ends the interval */
        if (seq < cf->entries[i].seq) continue;
        free(cf->entries[i].val);
        cf->entries[i].val = NULL;
        cf->entries[i].vlen = 0;
        cf->entries[i].seq = seq;
        cf->entries[i].tombstone = 1;
        cf->entries[i].deadline = FM_TTL_NONE;
    }
}

/* apply a whole buffered batch at one sequence, skipping a family the batch outlived. the ops go in
 * buffer order, so an interval tombstones what the batch wrote before it and leaves what it wrote
 * after */
static void fm_apply_batch(fuzz_model_t *m, const fm_op_t *ops, size_t count, uint64_t seq)
{
    for (size_t i = 0; i < count; i++)
    {
        fm_cf_t *cf = fm_cf_find_by_id(m, ops[i].cf_id);
        if (!cf) continue;
        if (ops[i].kind == FM_OP_RANGE_DELETE)
        {
            fm_apply_range(cf, &ops[i], seq);
            continue;
        }
        (void)fm_cf_apply(cf, ops[i].key, ops[i].klen, ops[i].val, ops[i].vlen,
                          ops[i].kind == FM_OP_DELETE, seq, ops[i].deadline);
    }
}

void fuzz_model_txn_begin(fuzz_model_t *m)
{
    if (m->txn_open) return;
    m->txn_open = 1;
    fm_buf_clear(m);
}

void fuzz_model_txn_commit(fuzz_model_t *m)
{
    if (!m->txn_open) return;

    /* a write-free commit takes no sequence, matching an engine commit that returns before it draws
     * one, which is what keeps the two clocks ordering writes the same way */
    if (m->buf_count > 0) fm_apply_batch(m, m->buf, m->buf_count, ++m->clock);

    fm_buf_clear(m);
    m->txn_open = 0;
}

void fuzz_model_txn_rollback(fuzz_model_t *m)
{
    if (!m->txn_open) return;
    fm_buf_clear(m);
    m->txn_open = 0;
}

int fuzz_model_txn_prepare(fuzz_model_t *m)
{
    if (!m || !m->txn_open || m->txn_prepared) return 0;

    /* a read-only transaction votes read-only and is finished outright, with no phase two to come
     */
    if (m->buf_count == 0)
    {
        fm_buf_clear(m);
        m->txn_open = 0;
        return 0;
    }

    /* the batch moves to its own buffer, since a transaction may begin and buffer writes of its own
     * while this one waits for a decision, and the two must not share storage. it takes no sequence
     * here -- phase two draws one when it decides, so the batch orders after everything that
     * committed while it was in doubt */
    m->pbuf = m->buf;
    m->pbuf_count = m->buf_count;
    m->pbuf_cap = m->buf_cap;
    m->buf = NULL;
    m->buf_count = 0;
    m->buf_cap = 0;
    m->sp_count = 0; /* savepoints belong to the transaction that just ended */
    m->txn_open = 0;
    m->txn_prepared = 1;
    return 1;
}

/* release the prepared batch's own storage */
static void fm_pbuf_clear(fuzz_model_t *m)
{
    for (size_t i = 0; i < m->pbuf_count; i++)
    {
        free(m->pbuf[i].key);
        free(m->pbuf[i].hi);
        free(m->pbuf[i].val);
    }
    free(m->pbuf);
    m->pbuf = NULL;
    m->pbuf_count = 0;
    m->pbuf_cap = 0;
    m->txn_prepared = 0;
}

int fuzz_model_commit_prepared(fuzz_model_t *m)
{
    if (!m || !m->txn_prepared) return 0;
    fm_apply_batch(m, m->pbuf, m->pbuf_count, ++m->clock);
    fm_pbuf_clear(m);
    return 1;
}

int fuzz_model_rollback_prepared(fuzz_model_t *m)
{
    if (!m || !m->txn_prepared) return 0;
    fm_pbuf_clear(m);
    return 1;
}

int fuzz_model_prepared_open(const fuzz_model_t *m)
{
    return m ? m->txn_prepared : 0;
}

/* whether a committing entry is one the engine must refuse against a held one. the engine claims an
 * interval against the other intervals only, and checks a point write against both the intervals
 * and the point reservations -- an interval cannot be claimed as a key hash, there being no one key
 * to hash. so a committing interval meeting a held point is not refused, and this is deliberately
 * not symmetric */
static int fm_op_refused_against(const fm_op_t *committing, const fm_op_t *held)
{
    if (committing->cf_id == 0 || committing->cf_id != held->cf_id) return 0;
    const int held_range = held->kind == FM_OP_RANGE_DELETE;

    if (committing->kind != FM_OP_RANGE_DELETE)
    {
        if (held_range) return fm_op_covers(held, committing->key, committing->klen);
        return fuzz_key_cmp(committing->key, committing->klen, held->key, held->klen) == 0;
    }

    if (!held_range) return 0;

    /* two half-open intervals intersect unless one ends at or below where the other starts; an open
     * upper bound is above every bound that can be spelled, so it never separates them */
    if (committing->hilen &&
        fuzz_key_cmp(committing->hi, committing->hilen, held->key, held->klen) <= 0)
        return 0;
    if (held->hilen && fuzz_key_cmp(held->hi, held->hilen, committing->key, committing->klen) <= 0)
        return 0;
    return 1;
}

int fuzz_model_txn_hits_prepared(const fuzz_model_t *m)
{
    if (!m || !m->txn_prepared || !m->txn_open) return 0;
    for (size_t i = 0; i < m->buf_count; i++)
        for (size_t j = 0; j < m->pbuf_count; j++)
            if (fm_op_refused_against(&m->buf[i], &m->pbuf[j])) return 1;
    return 0;
}

int fuzz_model_txn_open(const fuzz_model_t *m)
{
    return m->txn_open;
}

static long fm_sp_index(const fuzz_model_t *m, const char *name)
{
    for (size_t i = 0; i < m->sp_count; i++)
        if (strcmp(m->sps[i].name, name) == 0) return (long)i;
    return -1;
}

int fuzz_model_savepoint(fuzz_model_t *m, const char *name)
{
    if (!m->txn_open) return 0;
    const long idx = fm_sp_index(m, name);
    if (idx >= 0)
    {
        m->sps[idx].buf_len = m->buf_count;
        return 1;
    }
    if (m->sp_count == m->sp_cap)
    {
        const size_t nc = m->sp_cap ? m->sp_cap * 2 : 4;
        fm_sp_t *grown = realloc(m->sps, nc * sizeof(*grown));
        if (!grown) return 0;
        m->sps = grown;
        m->sp_cap = nc;
    }
    snprintf(m->sps[m->sp_count].name, sizeof(m->sps[m->sp_count].name), "%s", name);
    m->sps[m->sp_count].buf_len = m->buf_count;
    m->sp_count++;
    return 1;
}

/* truncate the buffer back to len, freeing the discarded ops */
static void fm_buf_truncate(fuzz_model_t *m, size_t len)
{
    for (size_t i = len; i < m->buf_count; i++)
    {
        free(m->buf[i].key);
        free(m->buf[i].hi);
        free(m->buf[i].val);
    }
    m->buf_count = len;
}

int fuzz_model_rollback_to(fuzz_model_t *m, const char *name)
{
    if (!m->txn_open) return 0;
    const long idx = fm_sp_index(m, name);
    if (idx < 0) return 0;
    fm_buf_truncate(m, m->sps[idx].buf_len);
    m->sp_count = (size_t)idx + 1; /* keep the target, drop savepoints taken after it */
    return 1;
}

int fuzz_model_release(fuzz_model_t *m, const char *name)
{
    if (!m->txn_open) return 0;
    const long idx = fm_sp_index(m, name);
    if (idx < 0) return 0;
    memmove(&m->sps[idx], &m->sps[idx + 1], (m->sp_count - (size_t)idx - 1) * sizeof(*m->sps));
    m->sp_count--;
    return 1;
}

/* append a buffered op (put or delete) for a cf */
static int fm_buf_append(fuzz_model_t *m, const char *cf, const fm_op_kind_t kind,
                         const uint8_t *key, size_t klen, const uint8_t *hi, size_t hilen,
                         const uint8_t *val, size_t vlen, int64_t deadline)
{
    if (!m->txn_open) return 0;
    const int is_put = kind == FM_OP_PUT;
    uint8_t *nk = fm_dup(key, klen);
    uint8_t *nh = hilen ? fm_dup(hi, hilen) : NULL;
    uint8_t *nv = is_put ? fm_dup(val, vlen) : NULL;
    if (!nk || (hilen && !nh) || (is_put && !nv))
    {
        free(nk);
        free(nh);
        free(nv);
        return 0;
    }
    if (m->buf_count == m->buf_cap)
    {
        const size_t nc = m->buf_cap ? m->buf_cap * 2 : 16;
        fm_op_t *grown = realloc(m->buf, nc * sizeof(*grown));
        if (!grown)
        {
            free(nk);
            free(nh);
            free(nv);
            return 0;
        }
        m->buf = grown;
        m->buf_cap = nc;
    }
    fm_op_t *op = &m->buf[m->buf_count++];
    const fm_cf_t *target = fm_cf_find(m, cf);
    op->cf_id = target ? target->id : 0;
    op->kind = kind;
    op->key = nk;
    op->klen = klen;
    op->hi = nh;
    op->hilen = hilen;
    op->val = nv;
    op->vlen = is_put ? vlen : 0;
    op->deadline = deadline;
    return 1;
}

int fuzz_model_put(fuzz_model_t *m, const char *cf, const uint8_t *key, size_t klen,
                   const uint8_t *val, size_t vlen, time_t ttl_seconds)
{
    return fm_buf_append(m, cf, FM_OP_PUT, key, klen, NULL, 0, val, vlen,
                         fm_ttl_deadline(ttl_seconds));
}

int fuzz_model_delete(fuzz_model_t *m, const char *cf, const uint8_t *key, size_t klen)
{
    return fm_buf_append(m, cf, FM_OP_DELETE, key, klen, NULL, 0, NULL, 0, FM_TTL_NONE);
}

int fuzz_model_delete_range(fuzz_model_t *m, const char *cf, const uint8_t *lo, size_t lolen,
                            const uint8_t *hi, size_t hilen)
{
    if (!m || !lo || lolen == 0) return 0;
    return fm_buf_append(m, cf, FM_OP_RANGE_DELETE, lo, lolen, hi, hilen, NULL, 0, FM_TTL_NONE);
}

int fuzz_model_delete_prefix(fuzz_model_t *m, const char *cf, const uint8_t *prefix, size_t plen)
{
    if (!m || !prefix || plen == 0) return 0;

    /* the successor rule is spelled out here rather than borrowed from the engine, so that the two
     * are compared against each other and not merely sharing one implementation of the same idea */
    size_t n = plen;
    while (n > 0 && prefix[n - 1] == FM_KEY_BYTE_MAX) n--;

    /* a prefix of nothing but max bytes has every key at or above it, so the interval it opens has
     * no upper bound to name */
    if (n == 0) return fuzz_model_delete_range(m, cf, prefix, plen, NULL, 0);

    uint8_t *hi = fm_dup(prefix, n);
    if (!hi) return 0;
    hi[n - 1]++;
    const int appended = fuzz_model_delete_range(m, cf, prefix, plen, hi, n);
    free(hi);
    return appended;
}

/* the buffered entry that decides (cf, key): the newest point write to it or interval delete
 * covering it, whichever was buffered later. returns a pointer into the buffer, or NULL when the
 * buffer says nothing about the key and the committed state decides it instead */
static const fm_op_t *fm_buf_decides(const fuzz_model_t *m, const char *cf, const uint8_t *key,
                                     size_t klen)
{
    const fm_cf_t *target = fm_cf_find(m, cf);
    if (!target) return NULL;
    for (long i = (long)m->buf_count - 1; i >= 0; i--)
    {
        const fm_op_t *op = &m->buf[i];
        if (op->cf_id != target->id) continue;
        if (op->kind == FM_OP_RANGE_DELETE)
        {
            if (fm_op_covers(op, key, klen)) return op;
            continue;
        }
        if (fuzz_key_cmp(op->key, op->klen, key, klen) == 0) return op;
    }
    return NULL;
}

int fuzz_model_get(const fuzz_model_t *m, const char *cf, const uint8_t *key, size_t klen,
                   const uint8_t **out_val, size_t *out_vlen)
{
    const fm_cf_t *c = fm_cf_find(m, cf);
    if (!c) return 0;

    if (m->txn_open)
    {
        const fm_op_t *op = fm_buf_decides(m, cf, key, klen);
        if (op)
        {
            if (op->kind != FM_OP_PUT || !fm_entry_live(op->deadline)) return 0;
            *out_val = op->val;
            *out_vlen = op->vlen;
            return 1;
        }
    }
    const long found = fm_cf_search(c, key, klen);
    if (found < 0 || c->entries[found].tombstone) return 0;
    if (!fm_entry_live(c->entries[found].deadline)) return 0;
    *out_val = c->entries[found].val;
    *out_vlen = c->entries[found].vlen;
    return 1;
}

int fuzz_model_get_committed(const fuzz_model_t *m, const char *cf, const uint8_t *key, size_t klen,
                             const uint8_t **out_val, size_t *out_vlen)
{
    const fm_cf_t *c = fm_cf_find(m, cf);
    if (!c) return 0;
    const long found = fm_cf_search(c, key, klen);
    if (found < 0 || c->entries[found].tombstone) return 0;
    if (!fm_entry_live(c->entries[found].deadline)) return 0;
    *out_val = c->entries[found].val;
    *out_vlen = c->entries[found].vlen;
    return 1;
}

int fuzz_model_debug_entry(const fuzz_model_t *m, const char *cf, const uint8_t *key,
                           const size_t klen, int *out_tombstone, uint64_t *out_seq)
{
    if (out_tombstone) *out_tombstone = 0;
    if (out_seq) *out_seq = 0;
    if (!m || !cf || !key) return 0;
    const fm_cf_t *c = fm_cf_find(m, cf);
    if (!c) return 0;
    const long found = fm_cf_search(c, key, klen);
    if (found < 0) return 0;
    if (out_tombstone) *out_tombstone = c->entries[found].tombstone;
    if (out_seq) *out_seq = c->entries[found].seq;
    return 1;
}

int fuzz_model_cf_count(const fuzz_model_t *m)
{
    return m ? (int)m->cf_count : 0;
}

const char *fuzz_model_cf_name_at(const fuzz_model_t *m, const int index)
{
    if (!m || index < 0 || (size_t)index >= m->cf_count) return NULL;
    return m->cfs[index].name;
}

int fuzz_model_scan(const fuzz_model_t *m, const char *cf, fuzz_model_kv_t **out, size_t *out_count)
{
    *out = NULL;
    *out_count = 0;
    const fm_cf_t *c = fm_cf_find(m, cf);
    if (!c) return 0;

    /* the committed set is already sorted; overlay the buffer by a per-key visibility check so each
     * key is emitted at most once in byte order */
    fuzz_model_kv_t *arr = malloc((c->count + (m->txn_open ? m->buf_count : 0) + 1) * sizeof(*arr));
    if (!arr) return 0;
    size_t n = 0;

    for (size_t i = 0; i < c->count; i++)
    {
        const uint8_t *val = c->entries[i].val;
        size_t vlen = c->entries[i].vlen;
        const fm_op_t *op =
            m->txn_open ? fm_buf_decides(m, cf, c->entries[i].key, c->entries[i].klen) : NULL;
        if (op)
        {
            /* the transaction deleted this committed key, by name or by covering it */
            if (op->kind != FM_OP_PUT) continue;
            if (!fm_entry_live(op->deadline)) continue;
            val = op->val;
            vlen = op->vlen;
        }
        else if (c->entries[i].tombstone || !fm_entry_live(c->entries[i].deadline))
            continue; /* a committed delete the open transaction did not resurrect, or an expiry */
        arr[n].key = c->entries[i].key;
        arr[n].klen = c->entries[i].klen;
        arr[n].val = val;
        arr[n].vlen = vlen;
        n++;
    }

    /* insert buffered puts for keys not present in the committed set, keeping the array byte-sorted
     */
    if (m->txn_open)
        for (size_t i = 0; i < m->buf_count; i++)
        {
            if (m->buf[i].cf_id != c->id || m->buf[i].kind != FM_OP_PUT) continue;
            if (!fm_entry_live(m->buf[i].deadline)) continue;
            /* a later interval covering this put decides the key instead, which is what the
             * identity test catches: the decider is then that interval and not this entry */
            if (fm_buf_decides(m, cf, m->buf[i].key, m->buf[i].klen) != &m->buf[i]) continue;
            if (fm_cf_search(c, m->buf[i].key, m->buf[i].klen) >= 0) continue; /* overlaid above */
            size_t pos = 0;
            while (pos < n &&
                   fuzz_key_cmp(arr[pos].key, arr[pos].klen, m->buf[i].key, m->buf[i].klen) < 0)
                pos++;
            memmove(&arr[pos + 1], &arr[pos], (n - pos) * sizeof(*arr));
            arr[pos].key = m->buf[i].key;
            arr[pos].klen = m->buf[i].klen;
            arr[pos].val = m->buf[i].val;
            arr[pos].vlen = m->buf[i].vlen;
            n++;
        }

    *out = arr;
    *out_count = n;
    return 1;
}
