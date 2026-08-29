/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "manifest/manifest_internal.h"

int tidesdb_manifest_add_cf(tidesdb_manifest_t *manifest, const uint64_t cf_id, const char *name,
                            const uint8_t *config_blob, size_t config_blob_len)
{
    if (!manifest || !name || strnlen(name, MANIFEST_CF_NAME_MAX) >= MANIFEST_CF_NAME_MAX)
        return -1;
    if (config_blob_len > MANIFEST_CF_BLOB_MAX) return -1;

    atomic_fetch_add(&manifest->active_ops, 1);
    tdb_wprwlock_wrlock(&manifest->lock);
    int result = manifest_cf_upsert_unlocked(manifest, cf_id, name, config_blob, config_blob_len);
    if (result == 0)
    {
        result = manifest_pending_add_cf_add(manifest, cf_id, name, config_blob, config_blob_len);
        if (result == 0) manifest->records_since_snapshot++;
    }
    tdb_wprwlock_unlock(&manifest->lock);
    /* raising the high-water here rather than at the call site means no path that assigns an id can
     * forget to, including a recovery that replays this family back in */
    if (result == 0) tidesdb_manifest_update_next_cf_id(manifest, cf_id + 1);
    atomic_fetch_sub(&manifest->active_ops, 1);
    return result;
}

int tidesdb_manifest_drop_cf(tidesdb_manifest_t *manifest, const uint64_t cf_id)
{
    if (!manifest) return -1;

    atomic_fetch_add(&manifest->active_ops, 1);
    tdb_wprwlock_wrlock(&manifest->lock);
    int result = -1;
    if (manifest_cf_drop_unlocked(manifest, cf_id))
    {
        result = manifest_pending_add_cf_drop(manifest, cf_id);
        if (result == 0) manifest->records_since_snapshot++;
    }
    tdb_wprwlock_unlock(&manifest->lock);
    atomic_fetch_sub(&manifest->active_ops, 1);
    return result;
}

int tidesdb_manifest_cf_id_by_name(tidesdb_manifest_t *manifest, const char *name, uint64_t *out_id)
{
    if (!manifest || !name || !out_id) return -1;

    atomic_fetch_add(&manifest->active_ops, 1);
    tdb_wprwlock_rdlock(&manifest->lock);
    int result = -1;
    for (int i = 0; i < manifest->num_cfs; i++)
    {
        if (strncmp(manifest->cfs[i].name, name, MANIFEST_CF_NAME_MAX) == 0)
        {
            *out_id = manifest->cfs[i].id;
            result = 0;
            break;
        }
    }
    tdb_wprwlock_unlock(&manifest->lock);
    atomic_fetch_sub(&manifest->active_ops, 1);
    return result;
}

int tidesdb_manifest_copy_cfs(tidesdb_manifest_t *manifest, tidesdb_manifest_cf_t *out,
                              const int max)
{
    if (!manifest) return 0;

    atomic_fetch_add(&manifest->active_ops, 1);
    tdb_wprwlock_rdlock(&manifest->lock);
    const int total = manifest->num_cfs;
    int copied = 0;
    if (out)
    {
        for (int i = 0; i < total && copied < max; i++) out[copied++] = manifest->cfs[i];
    }
    tdb_wprwlock_unlock(&manifest->lock);
    atomic_fetch_sub(&manifest->active_ops, 1);
    return out ? copied : total;
}

int tidesdb_manifest_self_healed(const tidesdb_manifest_t *manifest)
{
    return manifest ? manifest->self_healed : 0;
}

int tidesdb_manifest_add_sstable(tidesdb_manifest_t *manifest, const uint64_t cf_id,
                                 const int level, const uint64_t id, const uint64_t num_entries,
                                 const uint64_t size_bytes, const int partition)
{
    if (!manifest) return -1;

    atomic_fetch_add(&manifest->active_ops, 1);
    tdb_wprwlock_wrlock(&manifest->lock);
    /* a fresh add is born at this level, so birth_level equals level; only a move diverges them */
    int result = tidesdb_manifest_add_sstable_unlocked(manifest, cf_id, level, id, num_entries,
                                                       size_bytes, partition, level);
    if (result == 0)
    {
        result = manifest_pending_add_record(manifest, MANIFEST_OP_ADD_P, cf_id, level, id,
                                             num_entries, size_bytes, partition);
        if (result == 0) manifest->records_since_snapshot++;
    }
    tdb_wprwlock_unlock(&manifest->lock);
    atomic_fetch_sub(&manifest->active_ops, 1);
    return result;
}

int tidesdb_manifest_remove_sstable(tidesdb_manifest_t *manifest, const uint64_t cf_id,
                                    const int level, const uint64_t id)
{
    if (!manifest) return -1;

    atomic_fetch_add(&manifest->active_ops, 1);
    tdb_wprwlock_wrlock(&manifest->lock);
    int result = -1;
    if (manifest_remove_entry_unlocked(manifest, cf_id, level, id))
    {
        result = manifest_pending_add_record(manifest, MANIFEST_OP_REMOVE, cf_id, level, id, 0, 0,
                                             MANIFEST_NO_PARTITION);
        if (result == 0) manifest->records_since_snapshot++;
    }
    tdb_wprwlock_unlock(&manifest->lock);
    atomic_fetch_sub(&manifest->active_ops, 1);
    return result;
}

int tidesdb_manifest_copy_entries(tidesdb_manifest_t *manifest, const uint64_t cf_id,
                                  tidesdb_manifest_entry_t *out, const int max)
{
    if (!manifest) return 0;

    atomic_fetch_add(&manifest->active_ops, 1);
    tdb_wprwlock_rdlock(&manifest->lock);
    const int total = manifest->num_entries;
    int matched = 0;
    for (int i = 0; i < total; i++)
    {
        if (manifest->entries[i].column_family_id != cf_id) continue;
        if (out && matched < max) out[matched] = manifest->entries[i];
        matched++;
    }
    tdb_wprwlock_unlock(&manifest->lock);
    atomic_fetch_sub(&manifest->active_ops, 1);
    return matched;
}

int tidesdb_manifest_has_sstable(tidesdb_manifest_t *manifest, const uint64_t cf_id,
                                 const int level, const uint64_t id)
{
    if (!manifest) return 0;

    atomic_fetch_add(&manifest->active_ops, 1);
    tdb_wprwlock_rdlock(&manifest->lock);
    int at = manifest_index_find(manifest, cf_id, level, id);
    if (at == MANIFEST_INDEX_NO_INDEX)
    {
        at = -1;
        for (int i = 0; i < manifest->num_entries; i++)
            if (manifest->entries[i].column_family_id == cf_id &&
                manifest->entries[i].level == level && manifest->entries[i].id == id)
            {
                at = i;
                break;
            }
    }
    const int found = at >= 0;
    tdb_wprwlock_unlock(&manifest->lock);
    atomic_fetch_sub(&manifest->active_ops, 1);
    return found;
}

int tidesdb_manifest_find_level_by_id(tidesdb_manifest_t *manifest, const uint64_t cf_id,
                                      const uint64_t id)
{
    if (!manifest) return -1;

    atomic_fetch_add(&manifest->active_ops, 1);
    tdb_wprwlock_rdlock(&manifest->lock);
    /* asked once per key log on disk by the orphan sweep, so walking the entries here is the open
     * path paying the whole catalogue for every file it finds */
    int at = manifest_index_find(manifest, cf_id, -1, id);
    if (at == MANIFEST_INDEX_NO_INDEX)
    {
        at = -1;
        for (int i = 0; i < manifest->num_entries; i++)
            if (manifest->entries[i].column_family_id == cf_id && manifest->entries[i].id == id)
            {
                at = i;
                break;
            }
    }
    const int level = at >= 0 ? manifest->entries[at].level : -1;
    tdb_wprwlock_unlock(&manifest->lock);
    atomic_fetch_sub(&manifest->active_ops, 1);
    return level;
}

int tidesdb_manifest_move_sstable(tidesdb_manifest_t *manifest, const uint64_t cf_id,
                                  const uint64_t id, const int new_level)
{
    if (!manifest) return -1;

    atomic_fetch_add(&manifest->active_ops, 1);
    tdb_wprwlock_wrlock(&manifest->lock);
    int at = manifest_index_find(manifest, cf_id, -1, id);
    if (at == MANIFEST_INDEX_NO_INDEX)
    {
        at = -1;
        for (int i = 0; i < manifest->num_entries; i++)
            if (manifest->entries[i].column_family_id == cf_id && manifest->entries[i].id == id)
            {
                at = i;
                break;
            }
    }
    int result = -1;
    if (at >= 0)
    {
        /* the level moves but the key does not, so the index still names it */
        manifest->entries[at].level = new_level; /* birth_level, which names the file, is kept */
        result = 0;
    }
    if (result == 0)
    {
        result = manifest_pending_add_record(manifest, MANIFEST_OP_MOVE, cf_id, new_level, id, 0, 0,
                                             MANIFEST_NO_PARTITION);
        if (result == 0) manifest->records_since_snapshot++;
    }
    tdb_wprwlock_unlock(&manifest->lock);
    atomic_fetch_sub(&manifest->active_ops, 1);
    return result;
}

void tidesdb_manifest_update_sequence(tidesdb_manifest_t *manifest, uint64_t sequence)
{
    if (!manifest) return;

    /* monotonic guard -- the sequence seeds next_sstable_id on recovery, so it must never regress
     * or recovery would re-hand-out live sstable ids and collide. the value is persisted by the
     * next commit, which appends a SEQ record for the current sequence. */
    uint64_t cur = atomic_load(&manifest->sequence);
    while (sequence > cur && !atomic_compare_exchange_weak(&manifest->sequence, &cur, sequence))
    {
        /* cur reloaded with the live value on failure; loop re-checks sequence > cur */
    }
}

void tidesdb_manifest_update_next_cf_id(tidesdb_manifest_t *manifest, const uint64_t next_cf_id)
{
    if (!manifest) return;

    /* monotonic guard -- this high-water outlives the families it counted, so a drop must never let
     * it fall back onto an id whose records may still sit in an unreaped wal. the value is
     * persisted by the next commit, which appends a CF_SEQ record for the current high-water. */
    uint64_t cur = atomic_load(&manifest->next_cf_id);
    while (next_cf_id > cur &&
           !atomic_compare_exchange_weak(&manifest->next_cf_id, &cur, next_cf_id))
    {
        /* cur reloaded with the live value on failure; loop re-checks next_cf_id > cur */
    }
}

int tidesdb_manifest_hold(tidesdb_manifest_t *manifest, uint64_t *out_len)
{
    if (!manifest || !out_len) return -1;

    atomic_fetch_add(&manifest->active_ops, 1);
    /* the read lock is what a rollover's rename waits on, so the file the length describes is still
     * the file at the path for as long as the hold lasts */
    tdb_wprwlock_rdlock(&manifest->lock);
    if (manifest->bm && block_manager_get_size(manifest->bm, out_len) == 0) return 0;

    tdb_wprwlock_unlock(&manifest->lock);
    atomic_fetch_sub(&manifest->active_ops, 1);
    return -1;
}

void tidesdb_manifest_release(tidesdb_manifest_t *manifest)
{
    if (!manifest) return;

    tdb_wprwlock_unlock(&manifest->lock);
    atomic_fetch_sub(&manifest->active_ops, 1);
}
