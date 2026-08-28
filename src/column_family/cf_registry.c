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

/* how long a reader waits before looking again at whether the writer it is holding off for has got
 * in. only the engine's background sweeps take this lock, so a short sleep costs one of them a
 * little latency where a spin would cost a core */
#define CF_REGISTRY_WRITER_YIELD_US 200

/* an immutable published view of the registry, swapped whole on every membership change and read
 * without a lock. lookups are on the read path -- every transaction resolves its column family --
 * and a reader lock there would put an atomic read-modify-write on the shared lock word into every
 * read, and stall all of them whenever a rename or clone took the write lock. membership changes
 * are rare by comparison, so they pay a copy and the readers pay nothing
 * @cfs the family pointers, borrowed; the registry's locked array owns them
 * @count how many are live in this view */
typedef struct
{
    cf_t **cfs;
    int count;
} cf_registry_view_t;

struct cf_registry
{
    cf_t **cfs;
    int count;
    int capacity;
    _Atomic(uint64_t) next_cf_id;
    pthread_rwlock_t lock;
    /* how many writers are waiting on that lock, which is what holds new readers off long enough
     * for one of them to get in */
    _Atomic(int) writer_waiting;
    /* the published view, its reader guard, and the retire list superseded views wait on */
    _Atomic(cf_registry_view_t *) view;
    tdb_epoch_t view_epoch;
    tdb_retire_list_t view_retire;
};

/* free a superseded view; the family pointers it held are owned by the locked array, not by it */
static void cf_registry_view_reclaim(void *item, void *ctx)
{
    (void)ctx;
    cf_registry_view_t *v = (cf_registry_view_t *)item;
    free(v->cfs);
    free(v);
}

/* publish the locked array as a fresh immutable view and retire the previous one once the readers
 * that could still be inside it have drained. the caller holds the write lock, so the array is
 * stable while it is copied. on allocation failure the previous view stays published -- it would
 * then be missing this change, so every mutation treats that as a failure rather than continuing */
static int cf_registry_publish_locked(cf_registry_t *reg)
{
    cf_registry_view_t *fresh = malloc(sizeof(*fresh));
    if (!fresh) return TDB_ERR_MEMORY;
    fresh->cfs = reg->count ? malloc((size_t)reg->count * sizeof(*fresh->cfs)) : NULL;
    if (reg->count && !fresh->cfs)
    {
        free(fresh);
        return TDB_ERR_MEMORY;
    }
    if (reg->count) memcpy(fresh->cfs, reg->cfs, (size_t)reg->count * sizeof(*fresh->cfs));
    fresh->count = reg->count;

    cf_registry_view_t *old = atomic_exchange_explicit(&reg->view, fresh, memory_order_acq_rel);
    if (old) tdb_retire(&reg->view_retire, old, &reg->view_epoch, cf_registry_view_reclaim, NULL);
    return TDB_SUCCESS;
}

/* initialize the registry lock. a waiting writer is preferred over arriving readers, but by the
 * announcement in cf_registry_wrlock rather than by the lock's own kind.
 *
 * the readers are the engine's own background work -- every flush install, every compaction claim,
 * every reaper sweep -- and they arrive continuously under load. the writers are the caller's
 * create, drop, rename and clone. every rwlock admits an arriving reader while a writer waits
 * unless told otherwise, so a database that never stops flushing never lets the writer in at all,
 * and a create appears to hang while the process stays busy.
 *
 * the kind that says otherwise is a glibc extension, which left the guarantee holding on one
 * platform and the hang reachable on every other. announcing the writer instead is portable, so
 * this is a plain rwlock now and the preference lives in the two accessors.
 *
 * either way it is safe only because no reader takes the lock again while holding it. a reader that
 * did would wait on its own writer announcement and never reach the acquire that would have
 * completed, which is the same deadlock the nonrecursive attribute gave and for the same reason */
static int cf_registry_lock_init(pthread_rwlock_t *lock)
{
    return pthread_rwlock_init(lock, NULL);
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
    atomic_init(&reg->writer_waiting, 0);
    atomic_init(&reg->view, NULL);
    atomic_init(&reg->view_epoch, 0);
    if (cf_registry_lock_init(&reg->lock) != 0)
    {
        free(reg->cfs);
        free(reg);
        return NULL;
    }
    /* publish an empty view up front so a lookup before the first family never sees a null one */
    if (cf_registry_publish_locked(reg) != TDB_SUCCESS)
    {
        pthread_rwlock_destroy(&reg->lock);
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
    tdb_retire_drain(&reg->view_retire, NULL, NULL);
    cf_registry_view_t *v = atomic_load_explicit(&reg->view, memory_order_acquire);
    if (v) cf_registry_view_reclaim(v, NULL);
    pthread_rwlock_destroy(&reg->lock);
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

    cf_registry_wrlock(reg);

    if (cf_registry_index_of_name(reg, cf->name) >= 0)
    {
        cf_registry_wrunlock(reg);
        return TDB_ERR_EXISTS;
    }
    for (int i = 0; i < reg->count; i++)
        if (reg->cfs[i]->cf_id == cf->cf_id)
        {
            cf_registry_wrunlock(reg);
            return TDB_ERR_EXISTS;
        }

    if (reg->count == reg->capacity)
    {
        const int cap = reg->capacity * 2;
        cf_t **grown = realloc(reg->cfs, (size_t)cap * sizeof(*grown));
        if (!grown)
        {
            cf_registry_wrunlock(reg);
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
    cf_registry_wrunlock(reg);
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

    cf_registry_wrlock(reg);
    const int idx = cf_registry_index_of_name(reg, name);
    if (idx < 0)
    {
        cf_registry_wrunlock(reg);
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
        cf_registry_wrunlock(reg);
        return published;
    }
    cf_registry_wrunlock(reg);

    if (out)
        *out = detached;
    else
        cf_free(detached);
    return TDB_SUCCESS;
}

int cf_registry_rename_locked(cf_registry_t *reg, cf_t *cf, const char *new_name)
{
    if (!reg || !cf || !new_name) return TDB_ERR_INVALID_ARGS;

    if (cf_registry_index_of_name(reg, new_name) >= 0) return TDB_ERR_EXISTS;
    /* the name field is also the lookup key, so writing it under the write lock re-indexes the cf.
     * the view holds the same pointers, so it sees the new name immediately -- but it is
     * republished anyway so a lookup racing the write cannot observe a torn name through a stale
     * view */
    snprintf(cf->name, sizeof(cf->name), "%s", new_name);
    return cf_registry_publish_locked(reg);
}

uint64_t cf_registry_next_cf_id(cf_registry_t *reg)
{
    if (!reg) return 0;
    return atomic_fetch_add_explicit(&reg->next_cf_id, 1, memory_order_relaxed);
}

void cf_registry_rdlock(cf_registry_t *reg)
{
    if (!reg) return;

    /* hold off while a writer is waiting, so the gap it needs actually arrives. a reader that
     * slipped through between this load and the acquire below costs that writer one more reader
     * hold and nothing else, which is why an announcement is enough and a handoff is not needed */
    while (atomic_load_explicit(&reg->writer_waiting, memory_order_acquire) > 0)
        usleep(CF_REGISTRY_WRITER_YIELD_US);
    pthread_rwlock_rdlock(&reg->lock);
}

void cf_registry_rdunlock(cf_registry_t *reg)
{
    if (reg) pthread_rwlock_unlock(&reg->lock);
}

void cf_registry_wrlock(cf_registry_t *reg)
{
    if (!reg) return;

    /* announced before the acquire and withdrawn after it, so the readers held off are exactly the
     * ones that would otherwise have arrived while this writer waited */
    atomic_fetch_add_explicit(&reg->writer_waiting, 1, memory_order_release);
    pthread_rwlock_wrlock(&reg->lock);
    atomic_fetch_sub_explicit(&reg->writer_waiting, 1, memory_order_release);
}

void cf_registry_wrunlock(cf_registry_t *reg)
{
    if (reg) pthread_rwlock_unlock(&reg->lock);
}

int cf_registry_count_locked(const cf_registry_t *reg)
{
    return reg ? reg->count : 0;
}

cf_t *cf_registry_at_locked(const cf_registry_t *reg, int index)
{
    if (!reg || index < 0 || index >= reg->count) return NULL;
    return reg->cfs[index];
}
