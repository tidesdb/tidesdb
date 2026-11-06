/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/encoding/serialization.h" /* TDB_ID_MAX_DIGITS */
#include "base/log.h"
#include "sstable/vlog_internal.h"

/* how long a retire waits for readers to leave a drained segment before giving up and leaving it
 * for the next reclaim; a read holds its reference only across one block fetch, so this is far
 * longer than any real reader */
#define VLOG_RETIRE_WAIT_MAX 4096
#define VLOG_RETIRE_SLEEP_US 50

int vlog_segment_name(uint64_t number, char *out, size_t out_size)
{
    if (!out || out_size == 0) return VLOG_ERR_INVALID;
    const int n = snprintf(out, out_size, "%0*llu%s", VLOG_SEGMENT_DIGITS,
                           (unsigned long long)number, VLOG_SEGMENT_EXT);
    return (n > 0 && (size_t)n < out_size) ? VLOG_OK : VLOG_ERR_INVALID;
}

/* build dir/<segment name> into out */
static int vlog_segment_path(const vlog_t *v, uint64_t number, char *out, size_t out_size)
{
    char name[VLOG_SEGMENT_NAME_MAX];
    if (vlog_segment_name(number, name, sizeof(name)) != VLOG_OK) return VLOG_ERR_INVALID;
    const int n = snprintf(out, out_size, "%s%s%s", v->dir, PATH_SEPARATOR, name);
    return (n > 0 && (size_t)n < out_size) ? VLOG_OK : VLOG_ERR_INVALID;
}

/* parse a directory entry as a segment name, returning 1 and its number when it is one */
static int vlog_segment_parse_name(const char *name, uint64_t *out_number)
{
    const size_t ext_len = strlen(VLOG_SEGMENT_EXT);
    const size_t len = strlen(name);
    if (len <= ext_len) return 0;

    /* the extension identifies the kind and the leading digits the order, so anything else in the
     * directory -- a key log, the manifest, a partly written file -- is passed over */
    if (strcmp(name + (len - ext_len), VLOG_SEGMENT_EXT) != 0) return 0;

    /* a run longer than a uint64_t can hold would wrap into some other segment's number rather
     * than be rejected, so the width is bounded before it is accumulated */
    if (len - ext_len > TDB_ID_MAX_DIGITS) return 0;

    uint64_t number = 0;
    for (size_t i = 0; i < len - ext_len; i++)
    {
        if (name[i] < '0' || name[i] > '9') return 0;
        number = number * 10 + (uint64_t)(name[i] - '0');
    }
    *out_number = number;
    return 1;
}

/* insertion-sort the collected numbers ascending; the count is bounded by the segment table so the
 * quadratic cost is bounded with it, and a store is opened once */
static void vlog_segment_sort(uint64_t *numbers, size_t count)
{
    for (size_t i = 1; i < count; i++)
    {
        const uint64_t key = numbers[i];
        size_t j = i;
        while (j > 0 && numbers[j - 1] > key)
        {
            numbers[j] = numbers[j - 1];
            j--;
        }
        numbers[j] = key;
    }
}

/* a cursor finding no readable blocks can mean a torn tail. only the exact size and a valid
 * block-manager header prove that the file never held a value. */
static int vlog_segment_remove_empty(const char *path, int *removed)
{
    *removed = 0;
    struct STAT_STRUCT st;
    if (STAT_FUNC(path, &st) != 0) return VLOG_ERR_IO;
    if (st.st_size != BLOCK_MANAGER_HEADER_SIZE) return VLOG_OK;

    block_manager_t *bm = NULL;
    if (block_manager_open_pre(&bm, path, BLOCK_MANAGER_SYNC_NONE, 0) != 0) return VLOG_ERR_IO;
    uint64_t size = 0;
    const int sized = block_manager_get_size(bm, &size);
    const int closed = block_manager_close(bm);
    if (sized != 0 || closed != 0) return VLOG_ERR_IO;
    if (size != BLOCK_MANAGER_HEADER_SIZE) return VLOG_OK;
    if (remove(path) != 0) return VLOG_ERR_IO;
    *removed = 1;
    return VLOG_OK;
}

int vlog_segment_scan_dir(vlog_t *v, uint64_t *numbers, size_t max, size_t *out_count)
{
    if (!v || !numbers || !out_count) return VLOG_ERR_INVALID;
    *out_count = 0;

    DIR *d = opendir(v->dir);
    if (!d) return errno == ENOENT ? VLOG_OK : VLOG_ERR_IO;

    size_t count = 0;
    int rc = VLOG_OK;
    struct dirent *ent;
    for (;;)
    {
        errno = 0;
        ent = readdir(d);
        if (!ent)
        {
            if (errno != 0) rc = VLOG_ERR_IO;
            break;
        }
        uint64_t number = 0;
        if (!vlog_segment_parse_name(ent->d_name, &number)) continue;
        if (number == UINT64_MAX)
        {
            rc = VLOG_ERR_FULL; /* no fresh successor can be named */
            break;
        }
        /* recovery is the sole writer of next_number until the store is published */
        if (number >= atomic_load(&v->next_number)) atomic_store(&v->next_number, number + 1);

        char path[VLOG_PATH_MAX];
        const int n = snprintf(path, sizeof(path), "%s%s%s", v->dir, PATH_SEPARATOR, ent->d_name);
        if (n < 0 || (size_t)n >= sizeof(path))
        {
            rc = VLOG_ERR_INVALID;
            break;
        }
        int removed = 0;
        rc = vlog_segment_remove_empty(path, &removed);
        if (rc != VLOG_OK) break;
        if (removed)
        {
            if (vlog_sidecar_unlink(v, number) != VLOG_OK)
                TDB_DEBUG_LOG(TDB_LOG_WARN, "could not remove unused vlog index for %s", path);
            continue;
        }

        /* apply the slot limit after removing empty files, including in older stores */
        if (count >= max)
        {
            rc = VLOG_ERR_FULL;
            break;
        }
        numbers[count++] = number;
    }
    if (closedir(d) != 0 && rc == VLOG_OK) rc = VLOG_ERR_IO;

    if (rc != VLOG_OK) return rc;
    vlog_segment_sort(numbers, count);
    *out_count = count;
    return VLOG_OK;
}

/* claim the lowest free slot in the table, raising the high-water so scans stop early */
static int vlog_segment_claim_slot(vlog_t *v, uint32_t *out_slot)
{
    for (uint32_t i = 0; i < VLOG_MAX_SEGMENTS; i++)
    {
        if (atomic_load_explicit(&v->segments[i].state, memory_order_acquire) != VLOG_SEG_ABSENT)
            continue;
        *out_slot = i;
        uint32_t high = atomic_load_explicit(&v->seg_high, memory_order_relaxed);
        while (i + 1 > high &&
               !atomic_compare_exchange_weak_explicit(&v->seg_high, &high, i + 1,
                                                      memory_order_release, memory_order_relaxed))
        {
            /* another opener raised it first; re-read and retry only while ours is still higher */
        }
        return VLOG_OK;
    }
    return VLOG_ERR_FULL;
}

int vlog_segment_open(vlog_t *v, uint64_t number, uint32_t *out_slot)
{
    if (!v || !out_slot) return VLOG_ERR_INVALID;

    uint32_t slot = 0;
    const int claimed = vlog_segment_claim_slot(v, &slot);
    if (claimed != VLOG_OK) return claimed;

    char path[VLOG_PATH_MAX];
    if (vlog_segment_path(v, number, path, sizeof(path)) != VLOG_OK) return VLOG_ERR_INVALID;

    /* opened through the budget when there is one, so descriptor exhaustion wakes the reaper and
     * retries rather than failing the store outright */
    block_manager_t *bm = NULL;
    const int opened =
        v->fdm ? fd_manager_bm_open(v->fdm, &bm, path, v->sync_mode, FD_LABEL_VLOG_SEGMENT)
               : block_manager_open(&bm, path, v->sync_mode);
    if (opened != 0) return VLOG_ERR_IO;
    if (v->fdm) fd_manager_note_open(v->fdm, FD_LABEL_VLOG_SEGMENT);

    atomic_store_explicit(&v->segments[slot].bm, bm, memory_order_relaxed);
    v->segments[slot].number = number;
    atomic_store_explicit(&v->segments[slot].rc, VLOG_SEG_BASELINE, memory_order_relaxed);

    /* a retired segment leaves its liveness behind in the slot, and slots are reused, so the fresh
     * segment starts from nothing rather than inheriting what its predecessor was holding */
    atomic_store_explicit(&v->segments[slot].live_bytes, 0, memory_order_relaxed);
    atomic_store_explicit(&v->segments[slot].live_count, 0, memory_order_relaxed);

    /* published last and with release ordering, so a thread that observes the slot open also
     * observes the block manager and number stored above it */
    atomic_store_explicit(&v->segments[slot].state, VLOG_SEG_OPEN, memory_order_release);

    uint64_t next = atomic_load_explicit(&v->next_number, memory_order_relaxed);
    while (number + 1 > next &&
           !atomic_compare_exchange_weak_explicit(&v->next_number, &next, number + 1,
                                                  memory_order_release, memory_order_relaxed))
    {
        /* another opener raised it first; retry only while ours is still higher */
    }

    *out_slot = slot;
    return VLOG_OK;
}

int vlog_segment_acquire(vlog_t *v, uint32_t slot)
{
    if (!v || slot >= VLOG_MAX_SEGMENTS) return 0;
    if (atomic_load_explicit(&v->segments[slot].state, memory_order_acquire) != VLOG_SEG_OPEN)
        return 0;
    return tdb_try_ref(&v->segments[slot].rc);
}

void vlog_segment_release(vlog_t *v, uint32_t slot)
{
    if (!v || slot >= VLOG_MAX_SEGMENTS) return;
    (void)tdb_unref(&v->segments[slot].rc);
}

int vlog_segment_retire(vlog_t *v, uint32_t slot)
{
    if (!v || slot >= VLOG_MAX_SEGMENTS) return VLOG_ERR_INVALID;
    if (atomic_load_explicit(&v->segments[slot].state, memory_order_acquire) != VLOG_SEG_OPEN)
        return VLOG_OK;

    /* wait for readers already inside to leave. new readers cannot arrive, because the caller
     * repointed every value that named this segment before calling and the index is what a reader
     * resolves through */
    int won = 0;
    for (int wait = 0; wait < VLOG_RETIRE_WAIT_MAX; wait++)
    {
        if (tdb_refcount_begin_evict(&v->segments[slot].rc, VLOG_SEG_BASELINE))
        {
            won = 1;
            break;
        }
        usleep(VLOG_RETIRE_SLEEP_US);
    }
    if (!won)
    {
        /* a read holds its reference across one block fetch, so the wait is far longer than any
         * real reader needs. exhausting it means the segment stays on disk holding space this pass
         * meant to return, and the next reclaim has to try again */
        TDB_DEBUG_LOG(TDB_LOG_WARN,
                      "vlog segment %llu still has readers after %d waits, left for a later pass",
                      (unsigned long long)v->segments[slot].number, VLOG_RETIRE_WAIT_MAX);
        return VLOG_ERR_IO;
    }

    /* the caller decided this slot was reclaimable against a reading of active_slot that a roll may
     * have overtaken since, so confirm it here, where the answer can no longer change. a roll opens
     * its successor, which then reads open and empty, and only afterwards publishes it as active,
     * all under roll_mu -- so read without the lock, a successor in that window looks sealed and
     * reclaimable, and retiring it had the roll publish a dead slot that every append then failed
     * to take. under the lock no roll is between the two, and a roll that starts later claims only
     * a slot reading absent, which this one does not until the store at the end of this function.
     * retiring the active segment would unlink the file taking appends and leave every appender
     * spinning on a slot that never reopens */
    pthread_mutex_lock(&v->roll_mu);
    const int active = slot == atomic_load_explicit(&v->active_slot, memory_order_acquire);
    pthread_mutex_unlock(&v->roll_mu);
    if (active)
    {
        /* nothing could have counted through the window, as above, so the baseline is restored
         * exactly and the segment goes back to resting */
        (void)tdb_refcount_end_evict(&v->segments[slot].rc, VLOG_SEG_BASELINE);
        return VLOG_ERR_BUSY;
    }

    char path[VLOG_PATH_MAX];
    const int have_path = vlog_segment_path(v, v->segments[slot].number, path, sizeof(path));

    block_manager_t *bm = atomic_exchange(&v->segments[slot].bm, NULL);
    if (bm)
    {
        (void)block_manager_close(bm);
        if (v->fdm) fd_manager_note_close(v->fdm, FD_LABEL_VLOG_SEGMENT);
    }
    /* unlink the cache first: an interruption can always rebuild it from a surviving segment. */
    if (have_path == VLOG_OK)
    {
        if (vlog_sidecar_unlink(v, v->segments[slot].number) != VLOG_OK)
            TDB_DEBUG_LOG(TDB_LOG_WARN, "could not remove retired vlog index for %s", path);
        if (remove(path) != 0)
            TDB_DEBUG_LOG(TDB_LOG_WARN, "could not remove retired vlog segment %s", path);
    }

    /* the slot is reusable only once it reads absent, and the block manager must already be gone
     * when it does, so this store is the last thing to happen */
    atomic_store_explicit(&v->segments[slot].state, VLOG_SEG_ABSENT, memory_order_release);
    return VLOG_OK;
}

/* roll_mu protects slot installation against retire. indexed rolls also hold exclusive writer
 * admission and pin the old segment so a descriptor reaper cannot close it during publication. */
static int vlog_roll_locked(vlog_t *v, uint32_t full_slot)
{
    if (atomic_load_explicit(&v->active_slot, memory_order_acquire) != full_slot) return VLOG_OK;

    const uint64_t number = atomic_load_explicit(&v->next_number, memory_order_acquire);
    uint32_t slot = 0;
    const int rc = vlog_segment_open(v, number, &slot);
    if (rc != VLOG_OK) return rc;

    if (v->enable_vlog_indexes)
    {
        block_manager_t *bm = vlog_segment_ensure_open(v, full_slot);
        uint64_t extent = 0;
        if (!bm || block_manager_get_size(bm, &extent) != 0 || block_manager_last_errno(bm) != 0)
            v->pending_incomplete = 1;
        vlog_publish_pending(v, full_slot, extent, VLOG_SIDECAR_SEALED);
    }
    atomic_store_explicit(&v->active_slot, slot, memory_order_release);
    return VLOG_OK;
}

int vlog_segment_roll(vlog_t *v, uint32_t full_slot)
{
    if (!v) return VLOG_ERR_INVALID;
    if (v->enable_vlog_indexes)
    {
        pthread_rwlock_wrlock(&v->seal_rw);
        if (full_slot != atomic_load_explicit(&v->active_slot, memory_order_acquire))
        {
            pthread_rwlock_unlock(&v->seal_rw);
            return VLOG_OK;
        }
        if (!vlog_segment_acquire(v, full_slot))
        {
            pthread_rwlock_unlock(&v->seal_rw);
            return VLOG_ERR_IO;
        }
    }
    pthread_mutex_lock(&v->roll_mu);
    const int rc = vlog_roll_locked(v, full_slot);
    pthread_mutex_unlock(&v->roll_mu);
    if (v->enable_vlog_indexes)
    {
        vlog_segment_release(v, full_slot);
        pthread_rwlock_unlock(&v->seal_rw);
    }
    return rc;
}

/* the caller pins this slot through both the physical append and its index update. a failed
 * descriptor is treated like a full segment so retry takes a fresh file. */
static int vlog_append_to_slot(vlog_t *v, uint32_t slot, const uint8_t *payload, uint32_t size,
                               vlog_sidecar_entry_t *entry)
{
    block_manager_t *bm = vlog_segment_ensure_open(v, slot);
    uint64_t extent = 0;
    if (!bm || block_manager_get_size(bm, &extent) != 0) return VLOG_ERR_IO;
    if (extent >= v->segment_target_bytes || block_manager_last_errno(bm) != 0)
        return VLOG_ERR_FULL;

    const int64_t offset = block_manager_write_raw(bm, payload, size);
    if (offset < 0) return VLOG_ERR_IO;
    entry->offset = (uint64_t)offset;
#ifdef TDB_FAULT_INJECTION
    if (v->after_append) v->after_append(v);
#endif
    pthread_rwlock_wrlock(&v->index_rw);
    const int rc = vlog_record_entry(v, slot, entry);
    pthread_rwlock_unlock(&v->index_rw);
    return rc;
}

/* drop shared admission before taking its exclusive side. every earlier reservation has then
 * completed its physical write and map update, or poisoned the descriptor. the roll and other
 * checkpoint contenders may have won in between, so recheck the slot and the byte threshold. */
static void vlog_checkpoint_active(vlog_t *v, uint32_t slot)
{
    pthread_rwlock_wrlock(&v->seal_rw);
    if (slot == atomic_load_explicit(&v->active_slot, memory_order_acquire) &&
        vlog_segment_acquire(v, slot))
    {
        block_manager_t *bm = vlog_segment_ensure_open(v, slot);
        uint64_t extent = 0;
        if (bm && block_manager_get_size(bm, &extent) == 0 && extent >= v->checkpoint_at)
        {
            /* rate-limit failed cache writes too. a previously published prefix stays usable. */
            v->checkpoint_at = extent + VLOG_CHECKPOINT_INTERVAL_BYTES;
            if (block_manager_last_errno(bm) == 0)
                vlog_publish_pending(v, slot, extent, VLOG_SIDECAR_PREFIX);
        }
        vlog_segment_release(v, slot);
    }
    pthread_rwlock_unlock(&v->seal_rw);
}

int vlog_segment_append(vlog_t *v, const uint8_t *payload, size_t payload_len,
                        vlog_sidecar_entry_t *entry)
{
    if (!v || !payload || !payload_len || payload_len > UINT32_MAX || !entry)
        return VLOG_ERR_INVALID;
    for (int attempt = 0; attempt < VLOG_APPEND_MAX_ATTEMPTS; attempt++)
    {
        if (v->enable_vlog_indexes) pthread_rwlock_rdlock(&v->seal_rw);
        const uint32_t slot = atomic_load_explicit(&v->active_slot, memory_order_acquire);
        int rc = VLOG_ERR_BUSY;
        if (vlog_segment_acquire(v, slot))
        {
            rc = vlog_append_to_slot(v, slot, payload, (uint32_t)payload_len, entry);
            vlog_segment_release(v, slot);
        }
        if (v->enable_vlog_indexes)
        {
            const int due = rc == VLOG_OK && entry->offset + entry->disk_len >= v->checkpoint_at;
            pthread_rwlock_unlock(&v->seal_rw);
            if (due) vlog_checkpoint_active(v, slot);
        }
        if (rc == VLOG_ERR_BUSY) continue;
        if (rc != VLOG_ERR_FULL) return rc;

        const int rolled = vlog_segment_roll(v, slot);
        if (rolled == VLOG_ERR_FULL)
            usleep(VLOG_APPEND_FULL_PAUSE_US);
        else if (rolled != VLOG_OK)
            return rolled;
    }
    return VLOG_ERR_FULL;
}

block_manager_t *vlog_segment_ensure_open(vlog_t *v, uint32_t slot)
{
    block_manager_t *bm = atomic_load_explicit(&v->segments[slot].bm, memory_order_acquire);
    if (bm) return bm;

    char path[VLOG_PATH_MAX];
    if (vlog_segment_path(v, v->segments[slot].number, path, sizeof(path)) != VLOG_OK) return NULL;

    block_manager_t *opened = NULL;
    const int rc =
        v->fdm ? fd_manager_bm_open(v->fdm, &opened, path, v->sync_mode, FD_LABEL_VLOG_SEGMENT)
               : block_manager_open(&opened, path, v->sync_mode);
    if (rc != 0) return NULL;

    block_manager_t *expected = NULL;
    if (atomic_compare_exchange_strong(&v->segments[slot].bm, &expected, opened))
    {
        if (v->fdm) fd_manager_note_open(v->fdm, FD_LABEL_VLOG_SEGMENT);
        return opened;
    }

    /* another thread reopened first, so this one is surplus and is closed uncounted */
    (void)block_manager_close(opened);
    return expected;
}

int vlog_segment_evict(vlog_t *v, uint32_t slot)
{
    if (atomic_load_explicit(&v->segments[slot].state, memory_order_acquire) != VLOG_SEG_OPEN)
        return 0;
    if (atomic_load_explicit(&v->segments[slot].bm, memory_order_acquire) == NULL) return 0;

    /* the segment taking appends is left alone. it is written on every spill, so taking its
     * descriptor would only be paid back immediately */
    if (slot == atomic_load_explicit(&v->active_slot, memory_order_acquire)) return 0;

    /* claims the window only when no reader is inside, so a read in flight is never closed under */
    if (!tdb_refcount_begin_evict(&v->segments[slot].rc, VLOG_SEG_BASELINE)) return 0;
    block_manager_t *bm = atomic_exchange(&v->segments[slot].bm, NULL);
    /* the restored count is always the baseline here, so there is nothing to act on -- a reader
     * acquires through tdb_try_ref, which waits the window out rather than counting through it, and
     * a release can only follow an acquire that would have failed the claim above */
    (void)tdb_refcount_end_evict(&v->segments[slot].rc, VLOG_SEG_BASELINE);

    if (!bm) return 0;
    (void)block_manager_close(bm);
    if (v->fdm) fd_manager_note_close(v->fdm, FD_LABEL_VLOG_SEGMENT);
    return 1;
}
