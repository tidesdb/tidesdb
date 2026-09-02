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
#include "base/log.h"      /* reporting a retire the allocator refused */

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
/* something a membership change replaced, waiting for the views that named it to die -- a dropped
 * family's handle, or a renamed family's old name. neither can be freed when the change publishes:
 * a flush holds a view by reference count for as long as its I/O takes, and it reads both the
 * handle and the name from that view, well after the short borrow guard has cleared */
typedef struct cf_retired
{
    void *item;
    tdb_reclaim_fn reclaim;
    struct cf_retired *next;
} cf_retired_t;

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
    /* the published view, the guard covering the window in which a borrow is taken, and the list a
     * superseded view waits on.
     *
     * nothing on a writer's path ever waits for that guard to clear. a writer that waits for a
     * moment with no reader in flight does not get one while readers outnumber the cores, which has
     * stalled a create for minutes through four different primitives. the guard is consulted, never
     * waited on: tdb_retire reclaims inline when it is already clear and defers otherwise */
    _Atomic(cf_registry_view_t *) view;
    tdb_epoch_t view_epoch;
    tdb_retire_list_t view_retire;
    /* views allocated and not yet freed, and the families waiting on them. a family is unreachable
     * once every view older than its drop is gone, and since publication is monotonic, one live
     * view means that view is the newest -- which does not name it. so the count reaching one
     * proves what a wait for it used to provide, and is read when a view dies rather than waited
     * for */
    _Atomic(int) live_views;
    cf_retired_t *retired; /* guarded by lock */
};

/* free a superseded view; the family pointers it held are owned by the locked array, not by it */
/* drop the publication's own reference to a view that is no longer published; the view itself goes
 * when the last borrow of it does */
static void cf_registry_view_unpublish(void *item, void *ctx);

/* reclaim for an item that is simply freed, which a displaced name is */
static void cf_registry_free_item(void *item, void *ctx)
{
    (void)ctx;
    free(item);
}

/* free the retired items no live view can still name, if that is provable right now. never waits --
 * neither for a view nor for the lock. not for a view because that is the stall; not for the lock
 * because this runs on whichever thread dropped the last borrow, which is usually a reader, and
 * because one of the paths that reaches it is a publish that already holds the lock. what it
 * declines to do here the reaper's sweep does later */
static void cf_registry_reclaim_families(cf_registry_t *reg)
{
    if (atomic_load_explicit(&reg->live_views, memory_order_acquire) > 1) return;
    if (pthread_mutex_trylock(&reg->lock) != 0) return;

    /* re-read under the lock, so a drop appending while this walks does not lose its entry. what
     * makes the count enough is that a family reaches this list only after the view without it is
     * published, so a live count of one is always a view that does not name it */
    cf_retired_t *take = NULL;
    if (atomic_load_explicit(&reg->live_views, memory_order_acquire) <= 1)
    {
        take = reg->retired;
        reg->retired = NULL;
    }
    pthread_mutex_unlock(&reg->lock);

    while (take)
    {
        cf_retired_t *next = take->next;
        take->reclaim(take->item, NULL);
        free(take);
        take = next;
    }
}

static void cf_registry_view_reclaim(void *item, void *ctx)
{
    cf_registry_t *reg = (cf_registry_t *)ctx;
    cf_registry_view_t *v = (cf_registry_view_t *)item;
    free(v->cfs);
    free(v);
    atomic_fetch_sub_explicit(&reg->live_views, 1, memory_order_release);
    cf_registry_reclaim_families(reg);
}

static void cf_registry_view_unpublish(void *item, void *ctx)
{
    cf_registry_t *reg = (cf_registry_t *)ctx;
    cf_registry_view_t *v = (cf_registry_view_t *)item;
    /* the publication's reference goes here; the view itself goes with whichever borrow is last,
     * so a reader still inside one keeps it alive without anything having waited for it */
    if (atomic_fetch_sub_explicit(&v->refs, 1, memory_order_acq_rel) == 1)
        cf_registry_view_reclaim(v, reg);
}

/* publish the locked array as a fresh immutable view and retire the previous one once the readers
 * that could still be inside it have drained. the caller holds the write lock, so the array is
 * stable while it is copied. on allocation failure the previous view stays published -- it would
 * then be missing this change, so every mutation treats that as a failure rather than continuing */
static int cf_registry_publish_locked(cf_registry_t *reg)
{
    cf_registry_view_t *fresh = malloc(sizeof(*fresh));
    if (!fresh) return TDB_ERR_MEMORY;
    /* one reference for being published. borrows add their own, and whoever drops the last one
     * frees it -- so a view outlives its publication for exactly as long as someone holds it */
    atomic_init(&fresh->refs, 1);
    fresh->cfs = reg->count ? malloc((size_t)reg->count * sizeof(*fresh->cfs)) : NULL;
    if (reg->count && !fresh->cfs)
    {
        free(fresh);
        return TDB_ERR_MEMORY;
    }
    if (reg->count) memcpy(fresh->cfs, reg->cfs, (size_t)reg->count * sizeof(*fresh->cfs));
    fresh->count = reg->count;
    atomic_fetch_add_explicit(&reg->live_views, 1, memory_order_relaxed);

    cf_registry_view_t *old = atomic_exchange_explicit(&reg->view, fresh, memory_order_acq_rel);
    if (!old) return TDB_SUCCESS;

    /* the displaced view's own reference is handed to the retire list rather than dropped here.
     * dropping it needs to know that no borrow is still between reading the published pointer and
     * counting itself in, and the only way to know that by waiting is to wait for the guard to
     * clear -- which is the stall. tdb_retire asks instead: clear now, reclaim now; otherwise leave
     * it for a later sweep. either way this returns */
    tdb_retire(&reg->view_retire, old, &reg->view_epoch, cf_registry_view_unpublish, reg);
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
    atomic_init(&reg->live_views, 0);
    reg->retired = NULL;
    if (pthread_mutex_init(&reg->lock, NULL) != 0)
    {
        free(reg->cfs);
        free(reg);
        return NULL;
    }
    /* publish an empty view up front so a lookup before the first family never sees a null one */
    if (cf_registry_publish_locked(reg) != TDB_SUCCESS)
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
    tdb_retire_sweep(&reg->view_retire);
    cf_registry_view_t *v = atomic_load_explicit(&reg->view, memory_order_acquire);
    if (v) cf_registry_view_reclaim(v, reg);
    /* and any dropped family the sweep above did not already take, which is how a database closed
     * while a view was still borrowed frees the families that view was holding back */
    cf_retired_t *r = reg->retired;
    while (r)
    {
        cf_retired_t *next = r->next;
        r->reclaim(r->item, NULL);
        free(r);
        r = next;
    }
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
    const int published = cf_registry_publish_locked(reg);
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
    const int published = cf_registry_publish_locked(reg);
    if (published != TDB_SUCCESS)
    {
        memmove(&reg->cfs[idx + 1], &reg->cfs[idx], (size_t)(reg->count - idx) * sizeof(*reg->cfs));
        reg->cfs[idx] = detached;
        reg->count++;
        cf_registry_unlock(reg);
        return published;
    }
    cf_registry_unlock(reg);

    if (out)
        *out = detached;
    else
        cf_free(detached);
    return TDB_SUCCESS;
}

/* queue one replaced item for the views that can still name it to release. the caller must have
 * published the view that omits it first, which is what makes a live count of one sufficient */
static void cf_registry_retire_item(cf_registry_t *reg, void *item, tdb_reclaim_fn reclaim)
{
    cf_retired_t *node = malloc(sizeof(*node));
    if (!node)
    {
        /* nothing left to defer with. the item is leaked rather than freed under a reader, which
         * costs memory where the alternative costs correctness */
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "no memory to retire a replaced registry item, leaking it");
        return;
    }
    node->item = item;
    node->reclaim = reclaim;

    pthread_mutex_lock(&reg->lock);
    node->next = reg->retired;
    reg->retired = node;
    pthread_mutex_unlock(&reg->lock);

    cf_registry_reclaim_families(reg);
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
    if (rc == TDB_SUCCESS) rc = cf_registry_publish_locked(reg);
    cf_registry_unlock(reg);

    /* the displaced name outlives this call for as long as the family handle does, and for the same
     * reason -- a flush reads it from a view it borrowed before the rename and copies it into an
     * sstable path, which is not bounded by the borrow guard but by that flush's I/O. so it goes on
     * the same queue the dropped handles do, released by the last view that could still name it */
    if (displaced_name) cf_registry_retire_item(reg, displaced_name, cf_registry_free_item);
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

void cf_registry_retire_cf(cf_registry_t *reg, cf_t *cf, tdb_reclaim_fn reclaim)
{
    if (!reg || !cf || !reclaim) return;

    /* the family is out of the published view, so nothing new can reach it -- but a view published
     * before the removal still names it, and a flush holds one of those by reference count for as
     * long as its I/O takes. freeing the handle here is a use after free, and waiting for those
     * views to die is the stall this registry exists to avoid. so it is queued, and freed by
     * whichever view dies last -- or by the reaper, if it was already the last */
    cf_registry_retire_item(reg, cf, reclaim);
}

void cf_registry_sweep(cf_registry_t *reg)
{
    if (!reg) return;
    /* views first, since a view freed here is one fewer holding a dropped family back */
    tdb_retire_sweep(&reg->view_retire);
    cf_registry_reclaim_families(reg);
}
