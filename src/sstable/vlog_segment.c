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

int vlog_segment_scan_dir(const char *dir, uint64_t *numbers, size_t max, size_t *out_count)
{
    if (!dir || !numbers || !out_count) return VLOG_ERR_INVALID;
    *out_count = 0;

    DIR *d = opendir(dir);
    if (!d) return VLOG_OK; /* no directory yet is a fresh store, not a failure */

    size_t count = 0;
    int rc = VLOG_OK;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL)
    {
        uint64_t number = 0;
        if (!vlog_segment_parse_name(ent->d_name, &number)) continue;
        if (count >= max)
        {
            rc = VLOG_ERR_FULL;
            break;
        }
        numbers[count++] = number;
    }
    closedir(d);

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
     * have overtaken since, so confirm it here, where the answer can no longer change. a slot only
     * becomes the active one by being claimed out of the table, and the claim takes slots reading
     * absent -- this one still reads open until the store at the end of this function -- so no roll
     * can select it from here on, and the reading below is final. retiring the active segment would
     * unlink the file taking appends and leave every appender spinning on a slot that never reopens
     */
    if (slot == atomic_load_explicit(&v->active_slot, memory_order_acquire))
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
    if (have_path == VLOG_OK) (void)remove(path);

    /* the slot is reusable only once it reads absent, and the block manager must already be gone
     * when it does, so this store is the last thing to happen */
    atomic_store_explicit(&v->segments[slot].state, VLOG_SEG_ABSENT, memory_order_release);
    return VLOG_OK;
}

int vlog_segment_roll(vlog_t *v, uint32_t full_slot)
{
    if (!v) return VLOG_ERR_INVALID;

    pthread_mutex_lock(&v->roll_mu);

    /* another thread may have rolled between the caller's size check and this lock, in which case
     * the active segment is no longer the one observed full and there is nothing to do */
    if (atomic_load_explicit(&v->active_slot, memory_order_acquire) != full_slot)
    {
        pthread_mutex_unlock(&v->roll_mu);
        return VLOG_OK;
    }

    const uint64_t number = atomic_load_explicit(&v->next_number, memory_order_acquire);
    uint32_t slot = 0;
    const int rc = vlog_segment_open(v, number, &slot);
    if (rc == VLOG_OK) atomic_store_explicit(&v->active_slot, slot, memory_order_release);

    pthread_mutex_unlock(&v->roll_mu);
    return rc;
}

int vlog_segment_append(vlog_t *v, const uint8_t *payload, size_t payload_len, uint32_t *out_slot,
                        uint64_t *out_offset)
{
    if (!v || !payload || payload_len == 0 || !out_slot || !out_offset) return VLOG_ERR_INVALID;

    for (int attempt = 0; attempt < VLOG_APPEND_MAX_ATTEMPTS; attempt++)
    {
        const uint32_t slot = atomic_load_explicit(&v->active_slot, memory_order_acquire);

        /* the slot read a moment ago may already be retired: a reclaim rolls the active segment and
         * may then drain the one it just sealed, so an appender can arrive at a slot that is on its
         * way out. that is a lost race rather than a failure -- retry and the next read finds the
         * segment that replaced it */
        if (!vlog_segment_acquire(v, slot)) continue;

        block_manager_t *bm = vlog_segment_ensure_open(v, slot);
        uint64_t size = 0;
        if (!bm || block_manager_get_size(bm, &size) != 0)
        {
            vlog_segment_release(v, slot);
            return VLOG_ERR_IO;
        }

        /* roll on the observed size rather than under a lock, so two appenders may both land in a
         * segment already at its target. overshooting by a block is harmless; serializing every
         * append behind a size check would not be */
        if (size >= v->segment_target_bytes)
        {
            vlog_segment_release(v, slot);
            const int rolled = vlog_segment_roll(v, slot);
            if (rolled == VLOG_ERR_FULL)
            {
                /* every slot is taken, which happens while writers are ahead of reclamation rather
                 * than because the store is genuinely out of room. wait for a retire and look
                 * again; the attempt budget is what stops this becoming an unbounded spin */
                usleep(VLOG_APPEND_FULL_PAUSE_US);
                continue;
            }
            if (rolled != VLOG_OK) return rolled;
            continue;
        }

        const int64_t offset = block_manager_write_raw(bm, payload, (uint32_t)payload_len);
        vlog_segment_release(v, slot);
        if (offset < 0) return VLOG_ERR_IO;

        *out_slot = slot;
        *out_offset = (uint64_t)offset;
        return VLOG_OK;
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
