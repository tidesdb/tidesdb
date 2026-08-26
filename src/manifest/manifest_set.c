/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "manifest/manifest_internal.h"

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
    while (i < manifest->num_entries)
    {
        if (manifest->entries[i].column_family_id == cf_id)
            manifest->entries[i] = manifest->entries[--manifest->num_entries];
        else
            i++;
    }

    i = 0;
    while (i < manifest->num_range_dels)
    {
        if (manifest->range_dels[i].cf_id == cf_id)
        {
            free(manifest->range_dels[i].blob);
            manifest->range_dels[i] = manifest->range_dels[--manifest->num_range_dels];
        }
        else
        {
            i++;
        }
    }
    return found;
}

int manifest_range_del_upsert_unlocked(tidesdb_manifest_t *manifest, const uint64_t cf_id,
                                       const uint8_t *blob, const uint32_t blob_len)
{
    /* copied before anything is disturbed, so a failed allocation leaves the family's existing set
     * exactly as it was */
    uint8_t *copy = NULL;
    if (blob && blob_len)
    {
        copy = malloc(blob_len);
        if (!copy) return -1;
        memcpy(copy, blob, blob_len);
    }

    for (int i = 0; i < manifest->num_range_dels; i++)
    {
        if (manifest->range_dels[i].cf_id != cf_id) continue;
        free(manifest->range_dels[i].blob);
        if (!copy)
        {
            /* an empty set is carried as no slot at all, so a family whose last fragment retired
             * costs nothing in the next snapshot */
            manifest->range_dels[i] = manifest->range_dels[--manifest->num_range_dels];
            return 0;
        }
        manifest->range_dels[i].blob = copy;
        manifest->range_dels[i].blob_len = blob_len;
        return 0;
    }

    if (!copy) return 0;

    if (manifest->num_range_dels == manifest->range_dels_capacity)
    {
        const int new_capacity = manifest->range_dels_capacity ? manifest->range_dels_capacity * 2
                                                               : MANIFEST_INITIAL_CAPACITY;
        tidesdb_manifest_range_del_t *grown = realloc(
            manifest->range_dels, (size_t)new_capacity * sizeof(tidesdb_manifest_range_del_t));
        if (!grown)
        {
            free(copy);
            return -1;
        }
        manifest->range_dels = grown;
        manifest->range_dels_capacity = new_capacity;
    }

    manifest->range_dels[manifest->num_range_dels].cf_id = cf_id;
    manifest->range_dels[manifest->num_range_dels].blob = copy;
    manifest->range_dels[manifest->num_range_dels].blob_len = blob_len;
    manifest->num_range_dels++;
    return 0;
}

int tidesdb_manifest_add_sstable_unlocked(tidesdb_manifest_t *manifest, const uint64_t cf_id,
                                          const int level, const uint64_t id,
                                          const uint64_t num_entries, const uint64_t size_bytes,
                                          const int partition, const int birth_level)
{
    /* a table is identified by its family, its level and its id together -- the same id sitting at
     * two levels names two tables, so only all three matching is a restatement of one */
    for (int i = 0; i < manifest->num_entries; i++)
    {
        if (manifest->entries[i].column_family_id != cf_id || manifest->entries[i].level != level ||
            manifest->entries[i].id != id)
            continue;
        manifest->entries[i].num_entries = num_entries;
        manifest->entries[i].size_bytes = size_bytes;
        manifest->entries[i].partition = partition;
        manifest->entries[i].birth_level = birth_level;
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
    return 0;
}

int manifest_remove_entry_unlocked(tidesdb_manifest_t *manifest, const uint64_t cf_id,
                                   const int level, const uint64_t id)
{
    for (int i = 0; i < manifest->num_entries; i++)
    {
        if (manifest->entries[i].column_family_id != cf_id || manifest->entries[i].level != level ||
            manifest->entries[i].id != id)
            continue;
        manifest->entries[i] = manifest->entries[--manifest->num_entries];
        return 1;
    }
    return 0;
}
