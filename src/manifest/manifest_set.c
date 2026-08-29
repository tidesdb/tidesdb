/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "manifest/manifest_internal.h"

/* ===== the entry index =====
 *
 * the entries array is the truth and this only points into it. without it every add, every remove
 * and every lookup walks the whole array, so a database with tens of thousands of tables pays that
 * walk on each of them -- quadratic to replay a manifest, and paid again on every flush and
 * compaction output for as long as the database runs.
 *
 * the key is the family and the table id, which a database never reuses, so two entries sharing one
 * is not a thing that happens. the probe still compares the level a caller asked for and keeps
 * walking when it does not match, so the older behaviour of allowing the same id at two levels is
 * preserved rather than assumed away */

/* what a slot holds when nothing is there, and when something was and has since been erased. a
 * probe stops at EMPTY and steps over TOMB, so erasing never truncates another key's run */
#define MANIFEST_INDEX_EMPTY (-1)
#define MANIFEST_INDEX_TOMB  (-2)

/* the index is held at least twice the entry capacity so a probe walks a short run */
#define MANIFEST_INDEX_MIN_CAP 64

/* mix the two ids rather than concatenate them -- a database's ids are dense and low, so the raw
 * pair leaves the high bits of every key identical and every probe in one run */
static uint64_t manifest_index_hash(const uint64_t cf_id, const uint64_t id)
{
    uint64_t h = (cf_id + 0x9E3779B97F4A7C15ull) * 0xBF58476D1CE4E5B9ull;
    h ^= id + 0x9E3779B97F4A7C15ull + (h << 6) + (h >> 2);
    h *= 0x94D049BB133111EBull;
    return h ^ (h >> 31);
}

/* place the entry at slot into the index, which the caller has already sized to hold it */
static void manifest_index_place(tidesdb_manifest_t *manifest, const int slot)
{
    const tidesdb_manifest_entry_t *e = &manifest->entries[slot];
    const uint64_t mask = (uint64_t)manifest->index_cap - 1;
    uint64_t at = manifest_index_hash(e->column_family_id, e->id) & mask;
    /* a tombstone is reusable room. without taking it, a database that compacts for long enough
     * fills the table with them and every probe walks the whole of it */
    while (manifest->index[at] >= 0) at = (at + 1) & mask;
    if (manifest->index[at] == MANIFEST_INDEX_TOMB) manifest->index_tombs--;
    manifest->index[at] = slot;
}

/* rebuild the index over every entry, growing it to stay under half full. returns -1 when it could
 * not be allocated, which leaves the manifest without one and every lookup back on the walk */
static int manifest_index_rebuild(tidesdb_manifest_t *manifest)
{
    int cap = MANIFEST_INDEX_MIN_CAP;
    while (cap < manifest->capacity * 2) cap <<= 1;

    int *fresh = malloc((size_t)cap * sizeof(*fresh));
    if (!fresh) return -1;
    for (int i = 0; i < cap; i++) fresh[i] = MANIFEST_INDEX_EMPTY;

    free(manifest->index);
    manifest->index = fresh;
    manifest->index_cap = cap;
    manifest->index_tombs = 0;
    for (int i = 0; i < manifest->num_entries; i++) manifest_index_place(manifest, i);
    return 0;
}

/* the index position holding slot, or -1. used to erase or repoint one entry's mapping */
static int64_t manifest_index_position_of(const tidesdb_manifest_t *manifest, const int slot)
{
    if (!manifest->index || slot < 0 || slot >= manifest->num_entries) return -1;
    const tidesdb_manifest_entry_t *e = &manifest->entries[slot];
    const uint64_t mask = (uint64_t)manifest->index_cap - 1;
    uint64_t at = manifest_index_hash(e->column_family_id, e->id) & mask;
    for (int probed = 0; probed < manifest->index_cap; probed++)
    {
        if (manifest->index[at] == MANIFEST_INDEX_EMPTY) return -1;
        if (manifest->index[at] == slot) return (int64_t)at;
        at = (at + 1) & mask;
    }
    return -1;
}

int manifest_index_find(const tidesdb_manifest_t *manifest, const uint64_t cf_id, const int level,
                        const uint64_t id)
{
    if (!manifest->index) return MANIFEST_INDEX_NO_INDEX;

    const uint64_t mask = (uint64_t)manifest->index_cap - 1;
    uint64_t at = manifest_index_hash(cf_id, id) & mask;
    for (int probed = 0; probed < manifest->index_cap; probed++)
    {
        const int slot = manifest->index[at];
        if (slot == MANIFEST_INDEX_EMPTY) return -1;
        if (slot >= 0 && slot < manifest->num_entries)
        {
            const tidesdb_manifest_entry_t *e = &manifest->entries[slot];
            /* a negative level asks about the table wherever it sits, which is what a lookup by id
             * alone wants */
            if (e->column_family_id == cf_id && e->id == id && (level < 0 || e->level == level))
                return slot;
        }
        at = (at + 1) & mask;
    }
    return -1;
}

/* take the entry at slot out of the index, leaving a tombstone so the runs behind it still probe */
static void manifest_index_erase(tidesdb_manifest_t *manifest, const int slot)
{
    const int64_t at = manifest_index_position_of(manifest, slot);
    if (at < 0) return;
    manifest->index[at] = MANIFEST_INDEX_TOMB;
    manifest->index_tombs++;
}

void manifest_index_invalidate(tidesdb_manifest_t *manifest)
{
    free(manifest->index);
    manifest->index = NULL;
    manifest->index_cap = 0;
}

/**
 * manifest_cf_fill
 * write a family's id, name and opaque config blob into a registry slot
 * @param slot the registry slot to overwrite, cleared first so no byte of a previous occupant
 * survives past the length that describes it
 * @param cf_id stable column family id
 * @param name column family name, NUL-terminated
 * @param config_blob the family's serialized config, or NULL for none
 * @param config_blob_len length of config_blob in bytes
 */
static void manifest_cf_fill(tidesdb_manifest_cf_t *slot, const uint64_t cf_id, const char *name,
                             const uint8_t *config_blob, const size_t config_blob_len)
{
    const size_t name_len = strnlen(name, MANIFEST_CF_NAME_MAX - 1);
    const size_t blob_len =
        (config_blob && config_blob_len)
            ? (config_blob_len > MANIFEST_CF_BLOB_MAX ? MANIFEST_CF_BLOB_MAX : config_blob_len)
            : 0;

    memset(slot, 0, sizeof(*slot));
    slot->id = cf_id;
    memcpy(slot->name, name, name_len);
    if (blob_len) memcpy(slot->config_blob, config_blob, blob_len);
    slot->config_blob_len = (uint16_t)blob_len;
}

int manifest_cf_upsert_unlocked(tidesdb_manifest_t *manifest, const uint64_t cf_id,
                                const char *name, const uint8_t *config_blob,
                                size_t config_blob_len)
{
    if (!name) return -1;

    /* the id is the key, so re-registering one already known restates its name and config rather
     * than giving the family a second slot */
    for (int i = 0; i < manifest->num_cfs; i++)
    {
        if (manifest->cfs[i].id != cf_id) continue;
        manifest_cf_fill(&manifest->cfs[i], cf_id, name, config_blob, config_blob_len);
        return 0;
    }

    if (manifest->num_cfs == manifest->cfs_capacity)
    {
        const int new_capacity =
            manifest->cfs_capacity ? manifest->cfs_capacity * 2 : MANIFEST_INITIAL_CAPACITY;
        tidesdb_manifest_cf_t *grown =
            realloc(manifest->cfs, (size_t)new_capacity * sizeof(tidesdb_manifest_cf_t));
        if (!grown) return -1;
        manifest->cfs = grown;
        manifest->cfs_capacity = new_capacity;
    }

    manifest_cf_fill(&manifest->cfs[manifest->num_cfs], cf_id, name, config_blob, config_blob_len);
    manifest->num_cfs++;
    return 0;
}

int manifest_cf_drop_unlocked(tidesdb_manifest_t *manifest, const uint64_t cf_id)
{
    int found = 0;
    for (int i = 0; i < manifest->num_cfs; i++)
    {
        if (manifest->cfs[i].id != cf_id) continue;
        manifest->cfs[i] = manifest->cfs[manifest->num_cfs - 1];
        manifest->num_cfs--;
        found = 1;
        break;
    }

    /* everything the family owned goes with it, so a replay that stops after the drop cannot leave
     * an sstable or a tombstone set pointing at a family no longer registered */
    int i = 0;
    int dropped = 0;
    while (i < manifest->num_entries)
    {
        if (manifest->entries[i].column_family_id == cf_id)
        {
            manifest->entries[i] = manifest->entries[--manifest->num_entries];
            dropped = 1;
        }
        else
            i++;
    }

    /* the entries were rewritten in place rather than one at a time, so every slot the index named
     * may now hold something else. it is dropped and rebuilt on the next add */
    if (dropped) manifest_index_invalidate(manifest);
    return found;
}

int tidesdb_manifest_add_sstable_unlocked(tidesdb_manifest_t *manifest, const uint64_t cf_id,
                                          const int level, const uint64_t id,
                                          const uint64_t num_entries, const uint64_t size_bytes,
                                          const int partition, const int birth_level)
{
    /* a table is identified by its family, its level and its id together -- the same id sitting at
     * two levels names two tables, so only all three matching is a restatement of one */
    int found = manifest_index_find(manifest, cf_id, level, id);
    if (found == MANIFEST_INDEX_NO_INDEX)
    {
        found = -1;
        for (int i = 0; i < manifest->num_entries; i++)
            if (manifest->entries[i].column_family_id == cf_id &&
                manifest->entries[i].level == level && manifest->entries[i].id == id)
            {
                found = i;
                break;
            }
    }
    if (found >= 0)
    {
        manifest->entries[found].num_entries = num_entries;
        manifest->entries[found].size_bytes = size_bytes;
        manifest->entries[found].partition = partition;
        manifest->entries[found].birth_level = birth_level;
        return 0;
    }

    if (manifest->num_entries == manifest->capacity)
    {
        const int new_capacity =
            manifest->capacity ? manifest->capacity * 2 : MANIFEST_INITIAL_CAPACITY;
        tidesdb_manifest_entry_t *grown =
            realloc(manifest->entries, (size_t)new_capacity * sizeof(tidesdb_manifest_entry_t));
        if (!grown) return -1;
        manifest->entries = grown;
        manifest->capacity = new_capacity;
        /* the index is sized against the capacity, so it is rebuilt rather than outgrown */
        manifest_index_invalidate(manifest);
    }

    tidesdb_manifest_entry_t *slot = &manifest->entries[manifest->num_entries];
    slot->column_family_id = cf_id;
    slot->level = level;
    slot->id = id;
    slot->num_entries = num_entries;
    slot->size_bytes = size_bytes;
    slot->partition = partition;
    slot->birth_level = birth_level;
    manifest->num_entries++;
    /* a rebuild walks every entry, this one included, so placing it again afterwards would map it
     * twice and lengthen the probes behind it */
    if (manifest->index)
        manifest_index_place(manifest, manifest->num_entries - 1);
    else
        (void)manifest_index_rebuild(manifest);
    return 0;
}

int manifest_remove_entry_unlocked(tidesdb_manifest_t *manifest, const uint64_t cf_id,
                                   const int level, const uint64_t id)
{
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
    if (at < 0) return 0;

    /* the mapping goes before the entry does, since finding it reads the entry it names */
    manifest_index_erase(manifest, at);
    const int last = manifest->num_entries - 1;
    if (at != last)
    {
        manifest_index_erase(manifest, last);
        manifest->entries[at] = manifest->entries[last];
        if (manifest->index) manifest_index_place(manifest, at);
    }
    manifest->num_entries--;

    /* tombstones only ever lengthen a probe, so the table is rebuilt once they outnumber what it
     * actually holds */
    if (manifest->index && manifest->index_tombs > manifest->num_entries)
        (void)manifest_index_rebuild(manifest);
    return 1;
}
