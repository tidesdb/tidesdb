/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* the claims of a prepared batch whose handle was freed undecided, copied so they outlive it and
 * held in its place until the clock is destroyed */
#include <stdlib.h>
#include <string.h>

#include "mvcc_internal.h"

void mvcc_orphan_free(mvcc_orphan_t *o)
{
    for (int i = 0; i < o->n; i++) free(o->keys[i]);
    for (int i = 0; i < o->n_scans; i++) free(o->scan_bytes[i]);
    free(o->keys);
    free(o->claims);
    free(o->scan_bytes);
    free(o->scans);
    free(o);
}

/* copy a commit's scanned intervals, bounds included, into an orphan, 0 when the copies could not
 * all be made */
static int mvcc_orphan_copy_scans(mvcc_orphan_t *o, const tidesdb_mvcc_commit_t *commit)
{
    if (commit->n_scans <= 0) return 1;
    o->scans = calloc((size_t)commit->n_scans, sizeof(*o->scans));
    o->scan_bytes = calloc((size_t)commit->n_scans, sizeof(*o->scan_bytes));
    if (!o->scans || !o->scan_bytes) return 0;
    for (int i = 0; i < commit->n_scans; i++)
    {
        const tidesdb_mvcc_range_t *r = &commit->scans[i];
        uint8_t *bytes = malloc(r->lo_size + r->hi_size + 1);
        if (!bytes) return 0;
        memcpy(bytes, r->lo, r->lo_size);
        if (r->hi_size > 0) memcpy(bytes + r->lo_size, r->hi, r->hi_size);
        o->scan_bytes[i] = bytes;
        o->scans[i] = (tidesdb_mvcc_range_t){.cf_index = r->cf_index,
                                             .lo = bytes,
                                             .lo_size = r->lo_size,
                                             .hi = r->hi_size > 0 ? bytes + r->lo_size : NULL,
                                             .hi_size = r->hi_size};
        o->n_scans = i + 1;
    }
    return 1;
}

/* copy a commit's claims, key bytes included, into an orphan, or NULL when the copies could not
 * all be made */
static mvcc_orphan_t *mvcc_orphan_copy(const tidesdb_mvcc_commit_t *commit)
{
    mvcc_orphan_t *o = calloc(1, sizeof(*o));
    if (!o) return NULL;
    tidesdb_mvcc_commit_init(&o->commit, NULL, 0);
    if (commit->n_claims > 0)
    {
        o->claims = calloc((size_t)commit->n_claims, sizeof(*o->claims));
        o->keys = calloc((size_t)commit->n_claims, sizeof(*o->keys));
        if (!o->claims || !o->keys)
        {
            mvcc_orphan_free(o);
            return NULL;
        }
    }
    for (int i = 0; i < commit->n_claims; i++)
    {
        const tidesdb_mvcc_claim_t *c = &commit->claims[i];
        o->keys[i] = malloc(c->key_size ? c->key_size : 1);
        if (!o->keys[i])
        {
            mvcc_orphan_free(o);
            return NULL;
        }
        memcpy(o->keys[i], c->key, c->key_size);
        tidesdb_mvcc_claim_init(&o->claims[i], c->cf_index, o->keys[i], c->key_size, c->kind,
                                c->hash);
        o->claims[i].owner = &o->commit;
        o->n = i + 1;
    }
    if (!mvcc_orphan_copy_scans(o, commit))
    {
        mvcc_orphan_free(o);
        return NULL;
    }
    o->commit.claims = o->claims;
    o->commit.n_claims = o->n;
    o->commit.scans = o->scans;
    o->commit.n_scans = o->n_scans;
    atomic_store_explicit(&o->commit.seq, TDB_MVCC_SEQ_FUTURE, memory_order_release);
    return o;
}

/* put the orphan in the freed commit's place in the in-flight list, so an interval checked against
 * the list goes on meeting the batch's keys */
static void mvcc_inflight_replace(tidesdb_mvcc_t *m, tidesdb_mvcc_commit_t *commit,
                                  tidesdb_mvcc_commit_t *with)
{
    pthread_mutex_lock(&m->inflight_lock);
    for (tidesdb_mvcc_commit_t **link = &m->inflight; *link; link = &(*link)->next_inflight)
        if (*link == commit)
        {
            with->next_inflight = commit->next_inflight;
            *link = with;
            break;
        }
    commit->next_inflight = NULL;
    commit->held = 0;
    with->held = 1;
    pthread_mutex_unlock(&m->inflight_lock);
}

int tidesdb_mvcc_orphan_claims(tidesdb_mvcc_t *m, tidesdb_mvcc_commit_t *commit)
{
    if (!m || !commit || !commit->held) return 1;
    mvcc_orphan_t *o = mvcc_orphan_copy(commit);
    if (!o)
    {
        tidesdb_mvcc_unclaim(m, commit);
        return 0;
    }
    /* each copy takes its original's place in the chain under the same stripe lock, so no writer
     * of the key ever finds the key unheld between the two; the intervals change owner in place */
    for (int i = 0; i < commit->n_claims; i++)
    {
        const uint32_t bucket = mvcc_claim_bucket(commit->claims[i].hash);
        pthread_mutex_t *lock = mvcc_claim_stripe(m, bucket);
        pthread_mutex_lock(lock);
        mvcc_claim_unlink(m, bucket, &commit->claims[i]);
        o->claims[i].next = m->claim_heads[bucket];
        m->claim_heads[bucket] = &o->claims[i];
        pthread_mutex_unlock(lock);
    }
    pthread_mutex_lock(&m->range_lock);
    for (int i = 0; i < TDB_MVCC_MAX_RANGE_RESERVATIONS; i++)
        if (m->range_holds[i].in_use && m->range_holds[i].owner == commit)
            m->range_holds[i].owner = &o->commit;
    pthread_mutex_unlock(&m->range_lock);
    mvcc_inflight_replace(m, commit, &o->commit);
    commit->claims = NULL;
    commit->n_claims = 0;
    commit->scans = NULL;
    commit->n_scans = 0;
    pthread_mutex_lock(&m->orphan_lock);
    o->next = m->orphans;
    m->orphans = o;
    pthread_mutex_unlock(&m->orphan_lock);
    return 1;
}
