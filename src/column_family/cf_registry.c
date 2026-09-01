/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "cf_registry.h"

#include <stdlib.h>
#include <string.h>

#include "base/errors.h"   /* TDB_SUCCESS and the TDB_ERR_* result codes */
#include "base/lockfree.h" /* the reader epoch and retire list guarding the published view */
#include "compat.h"        /* usleep, for the reader hold-off */

/* the registry starts small and doubles; column families are few, so a linear array keyed by name
 * and id is simpler and cache-friendlier than a hash map */
#define CF_REGISTRY_INIT_CAP 8

/* an immutable published view of the registry, swapped whole on every membership change and read
 * without a lock. lookups are on the read path -- every transaction resolves its column family --
 * and a reader lock there would put an atomic read-modify-write on the shared lock word into every
 * read, and stall all of them whenever a rename or clone took the write lock. membership changes
 * are rare by comparison, so they pay a copy and the readers pay nothing
 * @param cfs the family pointers, borrowed; the registry's locked array owns them
 * @param count how many are live in this view */
struct cf_registry_view
{
    cf_t **cfs;
    int count;
    /* borrows outstanding on this view. the epoch covers only the window between reading the
     * published pointer and counting it, which is a few instructions; this covers the long hold,
     * and it is per view so an unpublished one's count can only fall */
    _Atomic(int) refs;
};

struct cf_registry
{
    cf_t **cfs;
    int count;
    int capacity;
    _Atomic(uint64_t) next_cf_id;
    /* the membership changes -- create, drop, rename, clone -- and nothing else. the engine's
     * background work reads the published view instead, so this excludes the other writers and no
     * reader waits behind it.
     *
     * it was a reader-writer lock while that background work took it for read. those readers arrive
     * continuously under load, which left a create waiting for a break in a stream that had none,
     * and on a platform that does not hand a waiting writer its turn promptly the wait ran to
     * minutes. no amount of preference in the lock fixed that; taking the readers off it did */
    pthread_mutex_t lock;
    /* the published view and the guard covering the window in which a borrow is taken. a superseded
     * view needs no retire list -- it is freed by whichever reference to it is dropped last.
     *
     * live_views counts every view still allocated, published or not. a removal has to wait out the
     * borrows of every view that still names the family, which is every view published before it --
     * waiting only on the one it displaced leaves a borrow of an older view holding a handle the
     * caller is about to free */
    _Atomic(cf_registry_view_t *) view;
    _Atomic(int) live_views;
    tdb_epoch_t view_epoch;
};

/* free a superseded view; the family pointers it held are owned by the locked array, not by it */
static void cf_registry_view_reclaim(void *item, void *ctx)
{
    cf_registry_t *reg = (cf_registry_t *)ctx;
    cf_registry_view_t *v = (cf_registry_view_t *)item;
    free(v->cfs);
    free(v);
    if (reg) atomic_fetch_sub_explicit(&reg->live_views, 1, memory_order_acq_rel);
}

/* publish the locked array as a fresh immutable view and retire the previous one once the readers
 * that could still be inside it have drained. the caller holds the write lock, so the array is
 * stable while it is copied. on allocation failure the previous view stays published -- it would
 * then be missing this change, so every mutation treats that as a failure rather than continuing */
static int cf_registry_publish_locked(cf_registry_t *reg, cf_registry_view_t **old_out)
{
    cf_registry_view_t *fresh = malloc(sizeof(*fresh));
    if (!fresh) return TDB_ERR_MEMORY;
    /* one reference for being published. borrows add their own, and whoever drops the last one
     * frees it -- so a view outlives its publication for exactly as long as someone holds it */
    atomic_init(&fresh->refs, 1);
    atomic_fetch_add_explicit(&reg->live_views, 1, memory_order_acq_rel);
    fresh->cfs = reg->count ? malloc((size_t)reg->count * sizeof(*fresh->cfs)) : NULL;
    if (reg->count && !fresh->cfs)
    {
        free(fresh);
        return TDB_ERR_MEMORY;
    }
    if (reg->count) memcpy(fresh->cfs, reg->cfs, (size_t)reg->count * sizeof(*fresh->cfs));
    fresh->count = reg->count;

    cf_registry_view_t *old = atomic_exchange_explicit(&reg->view, fresh, memory_order_acq_rel);
    if (!old) return TDB_SUCCESS;

    /* wait out the acquire windows before anything is decided about the old view, so no borrow can
     * still be between reading the published pointer and counting it. the window is a few
     * instructions, so this comes back at once however busy the readers are */
    tdb_epoch_wait_drained(&reg->view_epoch);

    /* a caller that must know when the old view is unused takes the publish reference from here and
     * drops it itself; otherwise it goes now, and the view is freed by whichever borrow is last */
    if (old_out)
        *old_out = old;
    else if (atomic_fetch_sub_explicit(&old->refs, 1, memory_order_acq_rel) == 1)
        cf_registry_view_reclaim(old, reg);
    return TDB_SUCCESS;
}

cf_registry_t *cf_registry_create(uint64_t next_cf_id)
{
    cf_registry_t *reg = calloc(1, sizeof(*reg));
    if (!reg) return NULL;
    reg->cfs = malloc(CF_REGISTRY_INIT_CAP * sizeof(*reg->cfs));
    if (!reg->cfs)
    {
        free(reg);
        return NULL;
    }
    reg->capacity = CF_REGISTRY_INIT_CAP;
    reg->count = 0;
    atomic_init(&reg->next_cf_id, next_cf_id);
    atomic_init(&reg->view, NULL);
    atomic_init(&reg->view_epoch, 0);
    if (pthread_mutex_init(&reg->lock, NULL) != 0)
    {
        free(reg->cfs);
        free(reg);
        return NULL;
    }
    /* publish an empty view up front so a lookup before the first family never sees a null one */
    if (cf_registry_publish_locked(reg, NULL) != TDB_SUCCESS)
    {
        (void)pthread_mutex_destroy(&reg->lock);
        free(reg->cfs);
        free(reg);
        return NULL;
    }
    return reg;
}

void cf_registry_destroy(cf_registry_t *reg)
{
    if (!reg) return;
    for (int i = 0; i < reg->count; i++) cf_free(reg->cfs[i]);
    free(reg->cfs);
    /* reclaim every superseded view, then the published one; no reader can be left by this point */
    cf_registry_view_t *v = atomic_load_explicit(&reg->view, memory_order_acquire);
    if (v) cf_registry_view_reclaim(v, reg);
    (void)pthread_mutex_destroy(&reg->lock);
    free(reg);
}

/* find the index of the cf with this name, or -1; the caller holds the lock */
static int cf_registry_index_of_name(const cf_registry_t *reg, const char *name)
{
    for (int i = 0; i < reg->count; i++)
        if (strncmp(reg->cfs[i]->name, name, TDB_MAX_CF_NAME_LEN) == 0) return i;
    return -1;
}

int cf_registry_add(cf_registry_t *reg, cf_t *cf)
{
    if (!reg || !cf) return TDB_ERR_INVALID_ARGS;

    cf_registry_lock(reg);

    if (cf_registry_index_of_name(reg, cf->name) >= 0)
    {
        cf_registry_unlock(reg);
        return TDB_ERR_EXISTS;
    }
    for (int i = 0; i < reg->count; i++)
        if (reg->cfs[i]->cf_id == cf->cf_id)
        {
            cf_registry_unlock(reg);
            return TDB_ERR_EXISTS;
        }

    if (reg->count == reg->capacity)
    {
        const int cap = reg->capacity * 2;
        cf_t **grown = realloc(reg->cfs, (size_t)cap * sizeof(*grown));
        if (!grown)
        {
            cf_registry_unlock(reg);
            return TDB_ERR_MEMORY;
        }
        reg->cfs = grown;
        reg->capacity = cap;
    }

    reg->cfs[reg->count++] = cf;
    /* the view is what every lookup reads, so a family that is not in it does not exist as far as
     * the read path is concerned. an append that cannot be published is undone rather than left
     * half-applied */
    const int published = cf_registry_publish_locked(reg, NULL);
    if (published != TDB_SUCCESS) reg->count--;
    cf_registry_unlock(reg);
    return published;
}

/* both lookups read the published view under the reader epoch rather than the registry lock. the
 * epoch keeps the view itself alive for the scan; it says nothing about the family the scan
 * returns, since a returned pointer outlives the critical section either way. what keeps a returned
 * family alive is that a drop removes it from the registry and waits out its compaction claim
 * before freeing it */
cf_t *cf_registry_get_by_name(cf_registry_t *reg, const char *name)
{
    if (!reg || !name) return NULL;

    tdb_epoch_enter(&reg->view_epoch);
    const cf_registry_view_t *v = atomic_load_explicit(&reg->view, memory_order_acquire);
    cf_t *cf = NULL;
    if (v)
        for (int i = 0; i < v->count; i++)
            if (strncmp(v->cfs[i]->name, name, TDB_MAX_CF_NAME_LEN) == 0)
            {
                cf = v->cfs[i];
                break;
            }
    tdb_epoch_exit(&reg->view_epoch);
    return cf;
}

cf_t *cf_registry_get_by_id(cf_registry_t *reg, uint64_t cf_id)
{
    if (!reg) return NULL;

    tdb_epoch_enter(&reg->view_epoch);
    const cf_registry_view_t *v = atomic_load_explicit(&reg->view, memory_order_acquire);
    cf_t *cf = NULL;
    if (v)
        for (int i = 0; i < v->count; i++)
            if (v->cfs[i]->cf_id == cf_id)
            {
                cf = v->cfs[i];
                break;
            }
    tdb_epoch_exit(&reg->view_epoch);
    return cf;
}

int cf_registry_remove(cf_registry_t *reg, const char *name, cf_t **out)
{
    if (!reg || !name) return TDB_ERR_INVALID_ARGS;

    cf_registry_lock(reg);
    const int idx = cf_registry_index_of_name(reg, name);
    if (idx < 0)
    {
        cf_registry_unlock(reg);
        return TDB_ERR_NOT_FOUND;
    }
    cf_t *detached = reg->cfs[idx];
    memmove(&reg->cfs[idx], &reg->cfs[idx + 1], (size_t)(reg->count - idx - 1) * sizeof(*reg->cfs));
    reg->count--;
    /* a removal that cannot be published would leave the dropped family still reachable through the
     * view while the caller went on to free it, so it is put back instead */
    cf_registry_view_t *displaced = NULL;
    const int published = cf_registry_publish_locked(reg, &displaced);
    if (published != TDB_SUCCESS)
    {
        memmove(&reg->cfs[idx + 1], &reg->cfs[idx], (size_t)(reg->count - idx) * sizeof(*reg->cfs));
        reg->cfs[idx] = detached;
        reg->count++;
        cf_registry_unlock(reg);
        return published;
    }
    /* the family is out of the published view, so nothing new can reach it. what can still be
     * holding it is a borrow of a view that named it, and the caller frees the handle the moment
     * this returns -- so those are waited out here rather than left to the caller. the registry
     * stays held across the wait so no other change can publish a view meanwhile; the readers being
     * waited for do not take it, so holding it costs them nothing */
    if (displaced) cf_registry_wait_readers_drained(reg, displaced);
    cf_registry_unlock(reg);

    if (out)
        *out = detached;
    else
        cf_free(detached);
    return TDB_SUCCESS;
}

int cf_registry_rename(cf_registry_t *reg, cf_t *cf, const char *new_name)
{
    if (!reg || !cf || !new_name) return TDB_ERR_INVALID_ARGS;

    cf_registry_lock(reg);
    if (cf_registry_index_of_name(reg, new_name) >= 0)
    {
        cf_registry_unlock(reg);
        return TDB_ERR_EXISTS;
    }
    char *displaced_name = NULL;
    int rc = cf_name_publish(cf, new_name, &displaced_name);
    cf_registry_view_t *displaced_view = NULL;
    if (rc == TDB_SUCCESS) rc = cf_registry_publish_locked(reg, &displaced_view);

    /* every reader that could still be copying the displaced name is either inside a borrow of a
     * view that named this family, waited out here, or holding the family's compaction claim, which
     * the caller took before asking for the rename. once both are past, nothing can reach it */
    if (displaced_view) cf_registry_wait_readers_drained(reg, displaced_view);
    cf_registry_unlock(reg);

    if (displaced_view) free(displaced_name);
    return rc;
}

uint64_t cf_registry_next_cf_id(cf_registry_t *reg)
{
    if (!reg) return 0;
    return atomic_fetch_add_explicit(&reg->next_cf_id, 1, memory_order_relaxed);
}

void cf_registry_lock(cf_registry_t *reg)
{
    if (reg) (void)pthread_mutex_lock(&reg->lock);
}

void cf_registry_unlock(cf_registry_t *reg)
{
    if (reg) (void)pthread_mutex_unlock(&reg->lock);
}

cf_registry_view_t *cf_registry_view_enter(cf_registry_t *reg, cf_t ***out_cfs, int *out_count)
{
    *out_cfs = NULL;
    *out_count = 0;
    if (!reg) return NULL;

    /* the epoch is held across the load and the count and nothing else, so waiting on it is a wait
     * on a few instructions rather than on however long a caller holds what it borrowed */
    tdb_epoch_enter(&reg->view_epoch);
    cf_registry_view_t *v = atomic_load_explicit(&reg->view, memory_order_acquire);
    if (v) atomic_fetch_add_explicit(&v->refs, 1, memory_order_acq_rel);
    tdb_epoch_exit(&reg->view_epoch);
    if (!v) return NULL;

    *out_cfs = v->cfs;
    *out_count = v->count;
    return v;
}

void cf_registry_view_leave(cf_registry_t *reg, cf_registry_view_t *view)
{
    if (view && atomic_fetch_sub_explicit(&view->refs, 1, memory_order_acq_rel) == 1)
        cf_registry_view_reclaim(view, reg);
}

void cf_registry_wait_readers_drained(cf_registry_t *reg, cf_registry_view_t *view)
{
    if (!reg || !view) return;

    /* the publish reference is still held here, so one is what remains when every borrow has gone.
     * the view is no longer published, so arriving borrows take the newer one and this count only
     * falls -- which is what makes the wait terminate under readers that never stop, where waiting
     * for no reader at all could not */
    while (atomic_load_explicit(&view->refs, memory_order_acquire) > 1) cpu_yield();

    if (atomic_fetch_sub_explicit(&view->refs, 1, memory_order_acq_rel) == 1)
        cf_registry_view_reclaim(view, reg);

    /* and every older view still borrowed, since each of those names the family too. they were
     * displaced by earlier changes and nobody waited on them, so a borrow of one outlives the wait
     * above -- and the caller frees the handle the moment this returns. no publish can add to the
     * count meanwhile because the caller holds the registry */
    while (atomic_load_explicit(&reg->live_views, memory_order_acquire) > 1) cpu_yield();
}
