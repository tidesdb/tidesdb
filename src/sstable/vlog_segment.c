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
#include "sstable/vlog_group_disk.h"
#include "sstable/vlog_internal.h"

/* how long a retire waits for readers to leave a drained segment before giving up and leaving it
 * for the next reclaim; a read holds its reference only across one block fetch, so this is far
 * longer than any real reader */
#define VLOG_RETIRE_WAIT_MAX 4096
#define VLOG_RETIRE_SLEEP_US 50

int vlog_segment_name(uint64_t number, char* out, size_t out_size)
{
    if (!out || out_size == 0) return VLOG_ERR_INVALID;
    const int n = snprintf(out, out_size, "%0*llu%s", VLOG_SEGMENT_DIGITS,
                           (unsigned long long)number, VLOG_SEGMENT_EXT);
    return (n > 0 && (size_t)n < out_size) ? VLOG_OK : VLOG_ERR_INVALID;
}

static int vlog_segment_path(const vlog_t* v, uint64_t number, uint32_t group, char* out,
                             size_t out_size)
{
    char name[VLOG_SEGMENT_NAME_MAX];
    if (vlog_segment_name(number, name, sizeof(name)) != VLOG_OK) return VLOG_ERR_INVALID;
    const char* subdir = group == VLOG_GROUP_UNGROUPED ? "" : VLOG_GROUP_GUARD_NAME PATH_SEPARATOR;
    const int n = snprintf(out, out_size, "%s%s%s%s", v->dir, PATH_SEPARATOR, subdir, name);
    return (n > 0 && (size_t)n < out_size) ? VLOG_OK : VLOG_ERR_INVALID;
}

/* parse a directory entry as a segment name, returning 1 and its number when it is one */
int vlog_segment_parse_number(const char* name, uint64_t* out_number)
{
    const size_t ext_len = strlen(VLOG_SEGMENT_EXT);
    const size_t len = strlen(name);
    if (len <= ext_len) return 0;

    /* the extension identifies the kind and the leading digits the order, so anything else in the
     * directory -- a key log, the manifest, a partly written file -- is passed over */
    if (strcmp(name + (len - ext_len), VLOG_SEGMENT_EXT) != 0) return 0;

    /* a run longer than a uint64_t can hold would wrap into some other segment's number rather
     * than be rejected, so the width is bounded before it is accumulated */
    const size_t number_len = len - ext_len;
    if (number_len > TDB_ID_MAX_DIGITS) return 0;

    uint64_t number = 0;
    for (size_t i = 0; i < number_len; i++)
    {
        if (name[i] < '0' || name[i] > '9') return 0;
        const uint64_t digit = (uint64_t)(name[i] - '0');
        if (number > (UINT64_MAX - digit) / 10) return 0;
        number = number * 10 + digit;
    }
    *out_number = number;
    return 1;
}

static int vlog_compare_numbers(const void* left, const void* right)
{
    const uint64_t a = *(const uint64_t*)left;
    const uint64_t b = *(const uint64_t*)right;
    return (a > b) - (a < b);
}

/* a cursor finding no readable blocks can mean a torn tail. only the exact size and a valid
 * block-manager header prove that the file never held a value. */
static int vlog_segment_remove_empty(const char* path, int grouped, int* removed)
{
    *removed = 0;
    struct STAT_STRUCT st;
    if (STAT_FUNC(path, &st) != 0) return VLOG_ERR_IO;
    const uint64_t empty_size = grouped ? vlog_group_disk_data_start(0) : BLOCK_MANAGER_HEADER_SIZE;
    if ((uint64_t)st.st_size != empty_size) return VLOG_OK;

    block_manager_t* bm = NULL;
    if (block_manager_open_pre(&bm, path, BLOCK_MANAGER_SYNC_NONE, 0) != 0) return VLOG_ERR_IO;
    uint64_t size = 0;
    const int sized = block_manager_get_size(bm, &size);
    const int closed = block_manager_close(bm);
    if (sized != 0 || closed != 0) return VLOG_ERR_IO;
    if (size != empty_size) return VLOG_OK;
    if (remove(path) != 0) return VLOG_ERR_IO;
    *removed = 1;
    return VLOG_OK;
}

int vlog_segment_scan_dir(vlog_t* v, int grouped, uint64_t* numbers, size_t max, size_t* out_count)
{
    if (!v || !numbers || !out_count) return VLOG_ERR_INVALID;
    *out_count = 0;
    char guard[VLOG_PATH_MAX];
    const char* dir = v->dir;
    if (grouped)
    {
        int n =
            snprintf(guard, sizeof(guard), "%s%s%s", dir, PATH_SEPARATOR, VLOG_GROUP_GUARD_NAME);
        if (n < 0 || (size_t)n >= sizeof(guard)) return VLOG_ERR_INVALID;
        dir = guard;
    }
    DIR* d = opendir(dir);
    if (!d) return errno == ENOENT ? VLOG_OK : VLOG_ERR_IO;

    size_t count = 0;
    int rc = VLOG_OK;
    for (;;)
    {
        errno = 0;
        struct dirent* ent = readdir(d);
        if (!ent)
        {
            if (errno != 0) rc = VLOG_ERR_IO;
            break;
        }
        uint64_t number;
        if (!vlog_segment_parse_number(ent->d_name, &number)) continue;
        if (number == UINT64_MAX)
        {
            /* the compatibility check already verified that the reserved root name is a directory
             */
            if (!grouped && strcmp(ent->d_name, VLOG_GROUP_GUARD_NAME) == 0) continue;
            rc = VLOG_ERR_FULL;
            break;
        }
        if (number >= atomic_load(&v->next_number)) atomic_store(&v->next_number, number + 1);

        char path[VLOG_PATH_MAX];
        const int n = snprintf(path, sizeof(path), "%s%s%s", dir, PATH_SEPARATOR, ent->d_name);
        if (n < 0 || (size_t)n >= sizeof(path))
        {
            rc = VLOG_ERR_INVALID;
            break;
        }
        int removed = 0;
        rc = vlog_segment_remove_empty(path, grouped, &removed);
        if (rc != VLOG_OK) break;
        if (removed)
        {
            if (vlog_sidecar_unlink(v, number) != VLOG_OK)
                TDB_DEBUG_LOG(TDB_LOG_WARN, "could not remove unused vlog index for %s", path);
            continue;
        }
        if (count >= max)
        {
            rc = VLOG_ERR_FULL;
            break;
        }
        numbers[count++] = number;
    }
    if (closedir(d) != 0 && rc == VLOG_OK) rc = VLOG_ERR_IO;
    if (rc != VLOG_OK) return rc;
    qsort(numbers, count, sizeof(*numbers), vlog_compare_numbers);
    *out_count = count;
    return VLOG_OK;
}

/* claim the lowest free slot in the table, raising the high-water so scans stop early */
static int vlog_segment_claim_slot(vlog_t* v, uint32_t* out_slot)
{
    for (uint32_t i = 0; i < v->max_segments; i++)
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

/* charge both cached and temporary descriptors against the same process budget */
static int vlog_segment_open_file(vlog_t* v, uint64_t number, uint32_t group, block_manager_t** bm)
{
    char path[VLOG_PATH_MAX];
    if (vlog_segment_path(v, number, group, path, sizeof(path)) != VLOG_OK) return VLOG_ERR_INVALID;

    const int rc = v->fdm
                       ? fd_manager_bm_open(v->fdm, bm, path, v->sync_mode, FD_LABEL_VLOG_SEGMENT)
                       : block_manager_open(bm, path, v->sync_mode);
    if (rc != 0) return VLOG_ERR_IO;
    if (v->fdm) fd_manager_note_open(v->fdm, FD_LABEL_VLOG_SEGMENT);
    return VLOG_OK;
}

static int vlog_segment_close_file(vlog_t* v, block_manager_t* bm)
{
    const int rc = block_manager_close(bm);
    if (v->fdm) fd_manager_note_close(v->fdm, FD_LABEL_VLOG_SEGMENT);
    return rc == 0 ? VLOG_OK : VLOG_ERR_IO;
}

static int vlog_segment_install(vlog_t* v, uint32_t slot, uint64_t number, uint32_t group,
                                block_manager_t* bm, uint32_t* out_slot)
{
    atomic_store_explicit(&v->segments[slot].bm, bm, memory_order_relaxed);
    v->segments[slot].number = number;
    v->segments[slot].group = group;
    if (v->max_blob_shard_groups) vlog_group_set_epoch(v, slot, UINT64_MAX);
    /* a retired segment leaves its liveness behind in the slot, and slots are reused, so the fresh
     * segment starts from nothing rather than inheriting what its predecessor was holding */
    atomic_store_explicit(&v->segments[slot].live_bytes, 0, memory_order_relaxed);
    atomic_store_explicit(&v->segments[slot].live_count, 0, memory_order_relaxed);
    atomic_store_explicit(&v->segments[slot].draining, 0, memory_order_relaxed);
    if (v->scrub) atomic_store_explicit(&v->scrub->sealed_extents[slot], 0, memory_order_relaxed);

    /* a ref acquired after observing an old OPEN can wait through retirement and win this new
     * baseline before it sees the new OPEN. release-publishing the baseline last gives that
     * acquire the complete new generation, including its reset scrub extent. */
    atomic_store_explicit(&v->segments[slot].rc, VLOG_SEG_BASELINE, memory_order_release);

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

int vlog_segment_adopt(vlog_t* v, uint64_t number, int grouped, uint32_t* out_slot)
{
    if (!v || !out_slot || number == UINT64_MAX) return VLOG_ERR_INVALID;
    uint32_t slot = 0;
    const int claimed = vlog_segment_claim_slot(v, &slot);
    if (claimed != VLOG_OK) return claimed;
    uint32_t group = grouped ? 0 : VLOG_GROUP_UNGROUPED;
    block_manager_t* bm = NULL;
    const int rc = vlog_segment_open_file(v, number, group, &bm);
    if (rc != VLOG_OK) return rc;
    if (grouped && (vlog_group_disk_read_owner(bm->fd, &group) != VLOG_OK ||
                    group >= v->max_blob_shard_groups))
    {
        (void)vlog_segment_close_file(v, bm); /* a rejected file cannot enter the slot table */
        return VLOG_ERR_CORRUPTION;
    }
    return vlog_segment_install(v, slot, number, group, bm, out_slot);
}

int vlog_segment_open(vlog_t* v, uint64_t number, uint32_t* out_slot)
{
    return vlog_segment_adopt(v, number, 0, out_slot);
}

int vlog_segment_create_group(vlog_t* v, uint64_t number, uint32_t group, uint32_t* out_slot)
{
    if (!v || !out_slot || group == VLOG_GROUP_UNGROUPED || number == UINT64_MAX)
        return VLOG_ERR_INVALID;
    uint32_t slot = 0;
    const int claimed = vlog_segment_claim_slot(v, &slot);
    if (claimed != VLOG_OK) return claimed;
    /* a failed directory sync or reopen may leave a metadata-only final file. never let an
     * ordinary roll or another group reuse its number before recovery cleans it. */
    atomic_store_explicit(&v->next_number, number + 1, memory_order_release);
    if (vlog_group_disk_guard_create(v->dir) != VLOG_OK) return VLOG_ERR_IO;

    char path[VLOG_PATH_MAX], temporary[VLOG_PATH_MAX];
    if (vlog_segment_path(v, number, group, path, sizeof(path)) != VLOG_OK) return VLOG_ERR_INVALID;
    const int temporary_n = snprintf(temporary, sizeof(temporary), "%s.tmp", path);
    if (temporary_n < 0 || (size_t)temporary_n >= sizeof(temporary)) return VLOG_ERR_INVALID;

    if (remove(temporary) != 0 && errno != ENOENT) return VLOG_ERR_IO;
    block_manager_t* bm = NULL;
    const int opened =
        v->fdm ? fd_manager_bm_open(v->fdm, &bm, temporary, v->sync_mode, FD_LABEL_VLOG_SEGMENT)
               : block_manager_open(&bm, temporary, v->sync_mode);
    if (opened != 0) return VLOG_ERR_IO;
    if (v->fdm) fd_manager_note_open(v->fdm, FD_LABEL_VLOG_SEGMENT);

    int rc = vlog_group_disk_write_header(bm, group);
    if (rc == VLOG_OK && block_manager_escalate_fsync(bm) != 0) rc = VLOG_ERR_IO;
    if (vlog_segment_close_file(v, bm) != VLOG_OK && rc == VLOG_OK) rc = VLOG_ERR_IO;
    if (rc != VLOG_OK)
    {
        (void)remove(temporary); /* an incomplete temporary is ignored and retried */
        return rc;
    }
    if (tdb_replace_file(temporary, path) != 0 || tdb_fsync_parent_dir(path) != 0)
    {
        (void)remove(temporary); /* an incomplete temporary is ignored and retried */
        return VLOG_ERR_IO;
    }
    block_manager_t* final = NULL;
    if (vlog_segment_open_file(v, number, group, &final) != VLOG_OK)
    {
        (void)remove(path); /* recovery also prunes validated metadata-only files */
        return VLOG_ERR_IO;
    }
    return vlog_segment_install(v, slot, number, group, final, out_slot);
}

int vlog_segment_acquire(vlog_t* v, uint32_t slot)
{
    if (!v || slot >= v->max_segments) return 0;
    if (atomic_load_explicit(&v->segments[slot].state, memory_order_acquire) != VLOG_SEG_OPEN)
        return 0;
    return tdb_try_ref(&v->segments[slot].rc);
}

void vlog_segment_release(vlog_t* v, uint32_t slot)
{
    if (!v || slot >= v->max_segments) return;
    (void)tdb_unref(&v->segments[slot].rc);
}

int vlog_segment_retire(vlog_t* v, uint32_t slot)
{
    if (!v || slot >= v->max_segments) return VLOG_ERR_INVALID;
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
    const int active = slot == atomic_load_explicit(&v->active_slot, memory_order_acquire) ||
                       vlog_group_slot_active(v, slot);
    pthread_mutex_unlock(&v->roll_mu);
    if (active)
    {
        /* nothing could have counted through the window, as above, so the baseline is restored
         * exactly and the segment goes back to resting */
        (void)tdb_refcount_end_evict(&v->segments[slot].rc, VLOG_SEG_BASELINE);
        return VLOG_ERR_BUSY;
    }

    char path[VLOG_PATH_MAX];
    const int have_path =
        vlog_segment_path(v, v->segments[slot].number, v->segments[slot].group, path, sizeof(path));

    block_manager_t* bm = atomic_exchange(&v->segments[slot].bm, NULL);
    if (bm) (void)vlog_segment_close_file(v, bm); /* reclaim unlinks the file below */
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

/* writer admission is exclusive here. the same seal publishes the optional index and
 * closes the builder protection interval for every route through the value log. */
static void vlog_seal_writer(vlog_t* v, uint32_t slot, vlog_pending_t* writer)
{
    if (v->enable_vlog_indexes || v->scrub)
    {
        block_manager_t* bm = vlog_segment_ensure_open(v, slot);
        uint64_t extent = 0;
        if (!bm || block_manager_get_size(bm, &extent) != 0 || block_manager_last_errno(bm) != 0)
            writer->incomplete = 1;
        else if (v->scrub)
            atomic_store_explicit(&v->scrub->sealed_extents[slot], extent, memory_order_release);
        if (v->enable_vlog_indexes)
            vlog_publish_pending(v, slot, writer, extent, VLOG_SIDECAR_SEALED);
    }
    if (v->max_blob_shard_groups) vlog_group_seal_epoch(v, slot);
}

/* roll_mu protects slot installation against retire. indexed rolls also hold exclusive writer
 * admission and pin the old segment so a descriptor reaper cannot close it during publication. */
static int vlog_roll_locked(vlog_t* v, uint32_t full_slot)
{
    if (atomic_load_explicit(&v->active_slot, memory_order_acquire) != full_slot) return VLOG_OK;

    const uint64_t number = atomic_load_explicit(&v->next_number, memory_order_acquire);
    uint32_t slot = 0;
    const int rc = vlog_segment_open(v, number, &slot);
    if (rc != VLOG_OK) return rc;

    vlog_seal_writer(v, full_slot, &v->writer);
    atomic_store_explicit(&v->active_slot, slot, memory_order_release);
    return VLOG_OK;
}

int vlog_segment_roll(vlog_t* v, uint32_t full_slot)
{
    if (!v) return VLOG_ERR_INVALID;
    if (v->use_seal_lock)
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
    if (v->use_seal_lock)
    {
        vlog_segment_release(v, full_slot);
        pthread_rwlock_unlock(&v->seal_rw);
    }
    return rc;
}

/* the caller pins this slot through both the physical append and its index update. a failed
 * descriptor is treated like a full segment so retry takes a fresh file. */
static int vlog_append_to_slot(vlog_t* v, uint32_t slot, vlog_pending_t* writer,
                               const struct iovec* spans, int count, vlog_sidecar_entry_t* entry)
{
    block_manager_t* bm = vlog_segment_ensure_open(v, slot);
    uint64_t extent = 0;
    if (!bm || block_manager_get_size(bm, &extent) != 0) return VLOG_ERR_IO;
    if ((extent >= v->segment_target_bytes &&
         (v->segments[slot].group == VLOG_GROUP_UNGROUPED ||
          extent != vlog_group_disk_data_start(v->segments[slot].group))) ||
        block_manager_last_errno(bm) != 0)
        return VLOG_ERR_FULL;

    const int64_t offset = block_manager_write_rawv(bm, spans, count);
    if (offset < 0) return VLOG_ERR_IO;
    entry->offset = (uint64_t)offset;
#ifdef TDB_FAULT_INJECTION
    if (v->after_append) v->after_append(v);
#endif
    pthread_rwlock_wrlock(&v->index_rw);
    const int rc = vlog_record_entry(v, slot, writer, entry);
    pthread_rwlock_unlock(&v->index_rw);
    return rc;
}

static void vlog_checkpoint_writer(vlog_t* v, uint32_t slot, vlog_pending_t* writer)
{
    block_manager_t* bm = vlog_segment_ensure_open(v, slot);
    uint64_t extent = 0;
    if (bm && block_manager_get_size(bm, &extent) == 0 && extent >= writer->checkpoint_at)
    {
        /* rate-limit failed cache writes too. a previously published prefix stays usable. */
        writer->checkpoint_at = extent + VLOG_CHECKPOINT_INTERVAL_BYTES;
        if (block_manager_last_errno(bm) == 0)
            vlog_publish_pending(v, slot, writer, extent, VLOG_SIDECAR_PREFIX);
    }
}

/* drop shared admission before taking its exclusive side. every earlier reservation has then
 * completed its physical write and map update, or poisoned the descriptor. the roll and other
 * checkpoint contenders may have won in between, so recheck the slot and the byte threshold. */
static void vlog_checkpoint_active(vlog_t* v, uint32_t slot)
{
    pthread_rwlock_wrlock(&v->seal_rw);
    if (slot == atomic_load_explicit(&v->active_slot, memory_order_acquire) &&
        vlog_segment_acquire(v, slot))
    {
        vlog_checkpoint_writer(v, slot, &v->writer);
        vlog_segment_release(v, slot);
    }
    pthread_rwlock_unlock(&v->seal_rw);
}

int vlog_segment_append(vlog_t* v, const struct iovec* spans, int count,
                        vlog_sidecar_entry_t* entry)
{
    if (!v || !spans || count <= 0 || !entry) return VLOG_ERR_INVALID;
    for (int attempt = 0; attempt < VLOG_APPEND_MAX_ATTEMPTS; attempt++)
    {
        if (v->use_seal_lock) pthread_rwlock_rdlock(&v->seal_rw);
        const uint32_t slot = atomic_load_explicit(&v->active_slot, memory_order_acquire);
        int rc = VLOG_ERR_BUSY;
        if (vlog_segment_acquire(v, slot))
        {
            rc = vlog_append_to_slot(v, slot, &v->writer, spans, count, entry);
            vlog_segment_release(v, slot);
        }
        if (v->use_seal_lock)
        {
            const int due = v->enable_vlog_indexes && rc == VLOG_OK &&
                            entry->offset + entry->disk_len >= v->writer.checkpoint_at;
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

/* take an exact route, or the oldest route with only the list's reference. scanning past
 * a busy writer lets the descriptor reaper continue without waiting on its I/O. */
static vlog_group_t* vlog_take_group(vlog_t* v, uint32_t id)
{
    vlog_group_t *match = NULL, *before = NULL, *prev = NULL;
    for (vlog_group_t* group = v->groups; group; group = group->next)
    {
        if (group->id == id || (id == VLOG_GROUP_UNGROUPED && atomic_load(&group->refs) == 1))
        {
            match = group;
            before = prev;
            if (group->id == id) break;
        }
        prev = group;
    }
    if (match)
    {
        if (before)
            before->next = match->next;
        else
            v->groups = match->next;
    }
    return match;
}

void vlog_group_unref(vlog_group_t* group)
{
    if (tdb_unref(&group->refs))
    {
        pthread_mutex_destroy(&group->append_mu);
        free(group->writer.entries);
        free(group);
    }
}

/* negative means every route is in use; zero can also mean a sealed file kept a reader's fd */
static int vlog_seal_oldest_locked(vlog_t* v)
{
    vlog_group_t* group = vlog_take_group(v, VLOG_GROUP_UNGROUPED);
    if (!group) return -1;
    vlog_seal_writer(v, group->slot, &group->writer);
    const int freed = vlog_segment_evict(v, group->slot);
    vlog_group_unref(group);
    return freed;
}

int vlog_seal_idle_groups(vlog_t* v, int max, int* out_freed)
{
    if (!v || max < 0) return VLOG_ERR_INVALID;
    if (out_freed) *out_freed = 0;
    if (!v->max_blob_shard_groups) return 0;
    int sealed = 0;
    /* a writer inside a descriptor-open retry may itself be waiting for the reaper. let the
     * reaper continue to other victims and revisit the writers on the next pass. */
    if (pthread_mutex_trylock(&v->roll_mu) != 0) return 0;
    while (v->groups && (!max || sealed < max))
    {
        const int freed = vlog_seal_oldest_locked(v);
        if (freed < 0) break;
        if (out_freed) *out_freed += freed;
        ++sealed;
    }
    pthread_mutex_unlock(&v->roll_mu);
    return sealed;
}

int vlog_backup_inventory(vlog_t* v, vlog_segment_info_t* out, size_t max, size_t* out_count)
{
    if (!v || !out || !out_count) return VLOG_ERR_INVALID;
    *out_count = 0;
    /* the backup cut has drained appenders before entering here. the default unindexed route needs
     * only its captured length, while a nonempty indexed route rolls to preserve its sealed cache.
     */
    const uint32_t active = atomic_load_explicit(&v->active_slot, memory_order_acquire);
    if (active < v->max_segments && v->enable_vlog_indexes)
    {
        uint64_t size = 0;
        if (vlog_segment_inspect(v, active, &size) != VLOG_OK) return VLOG_ERR_IO;
        if (size > BLOCK_MANAGER_HEADER_SIZE)
        {
            const int rolled = vlog_segment_roll(v, active);
            /* at the configured ceiling the captured prefix remains immutable. its optional
             * checkpoint can be rebuilt when the receiver opens with room for a successor. */
            if (rolled != VLOG_OK && rolled != VLOG_ERR_FULL) return rolled;
        }
    }
    if (v->max_blob_shard_groups)
    {
        /* the fd reaper can also seal idle groups during a transaction cut. */
        pthread_mutex_lock(&v->roll_mu);
        while (v->groups && vlog_seal_oldest_locked(v) >= 0)
        {
            /* each successful seal removes a route; a caller outside the cut can be busy */
        }
        const int busy = v->groups != NULL;
        pthread_mutex_unlock(&v->roll_mu);
        if (busy) return VLOG_ERR_BUSY;
    }
    const int rc = vlog_list_segments(v, out, max, out_count);
    if (rc != VLOG_OK || *out_count < VLOG_MAX_SEGMENTS) return rc;
    /* recovery prunes header-only files before adopting the rest. even the largest supported
     * receiver needs one usable slot for its fresh active segment. */
    for (size_t i = 0; i < *out_count; ++i)
        if (out[i].logical_size == vlog_group_disk_data_start(out[i].group)) return VLOG_OK;
    return VLOG_ERR_FULL;
}

/* roll_mu owns new file numbers and list membership. pin the route before releasing it so
 * a queued writer can safely wait on its own group without holding up unrelated groups. */
static int vlog_acquire_group_locked(vlog_t* v, uint32_t id, vlog_group_t** out)
{
    vlog_group_t* group = vlog_take_group(v, id);
    if (!group)
    {
        group = calloc(1, sizeof(*group));
        if (!group) return VLOG_ERR_MEMORY;
        if (pthread_mutex_init(&group->append_mu, NULL) != 0)
        {
            free(group);
            return VLOG_ERR_IO;
        }
        atomic_init(&group->refs, 1);
        if (v->fdm && fd_manager_open_total(v->fdm) >= fd_manager_open_budget(v->fdm))
            (void)vlog_seal_oldest_locked(v); /* make room for this group's first descriptor */
        group->id = id;
        group->writer.checkpoint_at =
            vlog_group_disk_data_start(id) + VLOG_CHECKPOINT_INTERVAL_BYTES;
        const uint64_t number = atomic_load_explicit(&v->next_number, memory_order_acquire);
        const int rc = vlog_segment_create_group(v, number, id, &group->slot);
        if (rc != VLOG_OK)
        {
            if (rc == VLOG_ERR_FULL)
                (void)vlog_seal_oldest_locked(v); /* GC can now reclaim an idle, dead segment */
            vlog_group_unref(group);
            return rc;
        }
    }
    group->next = v->groups;
    v->groups = group;
    tdb_ref(&group->refs);
    *out = group;
    return VLOG_OK;
}

static int vlog_group_append(vlog_t* v, uint32_t id, const struct iovec* spans, int count,
                             vlog_sidecar_entry_t* entry)
{
    vlog_group_t* group = NULL;
    pthread_mutex_lock(&v->roll_mu);
    const int admitted = vlog_acquire_group_locked(v, id, &group);
    pthread_mutex_unlock(&v->roll_mu);
    if (admitted != VLOG_OK) return admitted;

    /* an earlier writer can retire this route before a waiter wins append_mu. the waiter
     * still owns its route reference, sees the sentinel and retries against the new file. */
    int rc = VLOG_ERR_BUSY;
    pthread_mutex_lock(&group->append_mu);
    const uint32_t slot = group->slot;
    if (slot != VLOG_MAX_SEGMENTS && vlog_segment_acquire(v, slot))
    {
        rc = vlog_append_to_slot(v, slot, &group->writer, spans, count, entry);
        if (rc == VLOG_OK && v->enable_vlog_indexes &&
            entry->offset + entry->disk_len >= group->writer.checkpoint_at)
            vlog_checkpoint_writer(v, slot, &group->writer);
        if (rc == VLOG_ERR_FULL)
        {
            vlog_seal_writer(v, slot, &group->writer);
            pthread_mutex_lock(&v->roll_mu);
            (void)vlog_take_group(v, id); /* this route is still the unique owner of id */
            group->slot = VLOG_MAX_SEGMENTS;
            pthread_mutex_unlock(&v->roll_mu);
            vlog_group_unref(group); /* drop the list's reference; waiters retain theirs */
            rc = VLOG_ERR_BUSY;
        }
        vlog_segment_release(v, slot);
    }
    pthread_mutex_unlock(&group->append_mu);
    vlog_group_unref(group);
    return rc;
}

int vlog_segment_append_group(vlog_t* v, uint32_t id, const struct iovec* spans, int count,
                              vlog_sidecar_entry_t* entry)
{
    for (int attempt = 0; attempt < VLOG_APPEND_MAX_ATTEMPTS; ++attempt)
    {
        const int rc = vlog_group_append(v, id, spans, count, entry);
        if (rc == VLOG_ERR_FULL)
            usleep(VLOG_APPEND_FULL_PAUSE_US);
        else if (rc != VLOG_ERR_BUSY)
            return rc;
    }
    return VLOG_ERR_FULL;
}

block_manager_t* vlog_segment_ensure_open(vlog_t* v, uint32_t slot)
{
    block_manager_t* bm = atomic_load_explicit(&v->segments[slot].bm, memory_order_acquire);
    if (bm) return bm;

    block_manager_t* opened = NULL;
    if (vlog_segment_open_file(v, v->segments[slot].number, v->segments[slot].group, &opened) !=
        VLOG_OK)
        return NULL;

    block_manager_t* expected = NULL;
    if (atomic_compare_exchange_strong(&v->segments[slot].bm, &expected, opened)) return opened;

    (void)vlog_segment_close_file(v, opened); /* another reader installed the resident handle */
    return expected;
}

#ifdef TDB_FAULT_INJECTION
static void (*vlog_cold_borrow_hook)(block_manager_t* bm, int syncing);

void vlog_test_set_cold_borrow_hook(void (*hook)(block_manager_t* bm, int syncing))
{
    vlog_cold_borrow_hook = hook;
}
#endif

int vlog_segment_inspect(vlog_t* v, uint32_t slot, uint64_t* size)
{
    if (!v || slot >= v->max_segments) return VLOG_ERR_INVALID;
    vlog_segment_t* segment = &v->segments[slot];
    block_manager_t* bm = atomic_load_explicit(&segment->bm, memory_order_acquire);
    const int cold = bm == NULL;
    if (cold)
    {
        if (vlog_segment_open_file(v, segment->number, segment->group, &bm) != VLOG_OK)
            return VLOG_ERR_IO;
#ifdef TDB_FAULT_INJECTION
        if (vlog_cold_borrow_hook) vlog_cold_borrow_hook(bm, size == NULL);
#endif
    }

    const int rc = size ? block_manager_get_size(bm, size) : block_manager_escalate_fsync(bm);
    if (cold)
    {
        if (!size && rc != 0)
        {
            /* a clean retry can hide lost writes. retain the failed handle, or transfer its
             * first error to the handle installed by another borrower. our slot pin protects
             * that handle through the handoff without excluding other readers during fsync. */
            block_manager_t* installed = NULL;
            if (atomic_compare_exchange_strong(&segment->bm, &installed, bm)) return VLOG_ERR_IO;
            (void)block_manager_latch_error(installed, block_manager_last_errno(bm));
        }
        if (vlog_segment_close_file(v, bm) != VLOG_OK) return VLOG_ERR_IO;
    }
    /* a concurrent sync may have published an error while this one was in the kernel */
    if (!size && block_manager_last_errno(atomic_load_explicit(&segment->bm, memory_order_acquire)))
        return VLOG_ERR_IO;
    return rc == 0 ? VLOG_OK : VLOG_ERR_IO;
}

int vlog_segment_scrub_fd(vlog_t* v, uint32_t slot, int* out_fd, int* out_owned)
{
    if (!v || !out_fd || !out_owned || slot >= v->max_segments) return VLOG_ERR_INVALID;
    block_manager_t* bm = atomic_load_explicit(&v->segments[slot].bm, memory_order_acquire);
    if (bm)
    {
        *out_fd = bm->fd;
        *out_owned = 0;
        return VLOG_OK;
    }

    char path[VLOG_PATH_MAX];
    if (vlog_segment_path(v, v->segments[slot].number, v->segments[slot].group, path,
                          sizeof(path)) != VLOG_OK)
        return VLOG_ERR_INVALID;
    const int fd = open(path, O_RDONLY, 0);
    if (fd < 0) return VLOG_ERR_IO;
    fd_manager_note_open(v->fdm, FD_LABEL_VLOG_SEGMENT);
    *out_fd = fd;
    *out_owned = 1;
    return VLOG_OK;
}

int vlog_segment_evict(vlog_t* v, uint32_t slot)
{
    if (atomic_load_explicit(&v->segments[slot].state, memory_order_acquire) != VLOG_SEG_OPEN)
        return 0;
    if (atomic_load_explicit(&v->segments[slot].bm, memory_order_acquire) == NULL) return 0;

    /* the segment taking appends is left alone. it is written on every spill, so taking its
     * descriptor would only be paid back immediately */
    if (slot == atomic_load_explicit(&v->active_slot, memory_order_acquire) ||
        vlog_group_slot_active(v, slot))
        return 0;

    /* claims the window only when no reader is inside, so a read in flight is never closed under */
    if (!tdb_refcount_begin_evict(&v->segments[slot].rc, VLOG_SEG_BASELINE)) return 0;
    block_manager_t* bm = atomic_load_explicit(&v->segments[slot].bm, memory_order_relaxed);
    /* a fresh descriptor could report a clean sync for data the device already lost. keep the
     * failed handle until retirement so every durability barrier still sees its first error. */
    if (bm && block_manager_last_errno(bm) == 0)
        atomic_store_explicit(&v->segments[slot].bm, NULL, memory_order_release);
    else
        bm = NULL;
    /* the restored count is always the baseline here, so there is nothing to act on -- a reader
     * acquires through tdb_try_ref, which waits the window out rather than counting through it, and
     * a release can only follow an acquire that would have failed the claim above */
    (void)tdb_refcount_end_evict(&v->segments[slot].rc, VLOG_SEG_BASELINE);

    if (!bm) return 0;
    (void)vlog_segment_close_file(v, bm); /* this idle descriptor has already been detached */
    return 1;
}
