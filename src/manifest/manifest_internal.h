/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __MANIFEST_INTERNAL_H__
#define __MANIFEST_INTERNAL_H__

#include "manifest/manifest.h"

static inline void manifest_put_u16(uint8_t *p, const uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static inline void manifest_put_u32(uint8_t *p, const uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static inline void manifest_put_u64(uint8_t *p, uint64_t v)
{
    for (int i = 7; i >= 0; i--)
    {
        p[i] = (uint8_t)v;
        v >>= 8;
    }
}

static inline uint16_t manifest_get_u16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static inline uint32_t manifest_get_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline uint64_t manifest_get_u64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | (uint64_t)p[i];
    return v;
}

/* helpers shared across the manifest translation units; not part of the public api */
int manifest_cf_upsert_unlocked(tidesdb_manifest_t *manifest, const uint64_t cf_id,
                                const char *name, const uint8_t *config_blob,
                                size_t config_blob_len);
int manifest_cf_drop_unlocked(tidesdb_manifest_t *manifest, const uint64_t cf_id);
int tidesdb_manifest_add_sstable_unlocked(tidesdb_manifest_t *manifest, const uint64_t cf_id,
                                          const int level, const uint64_t id,
                                          const uint64_t num_entries, const uint64_t size_bytes,
                                          const int partition, const int birth_level);
int manifest_remove_entry_unlocked(tidesdb_manifest_t *manifest, const uint64_t cf_id,
                                   const int level, const uint64_t id);
int manifest_pending_add_cf_add(tidesdb_manifest_t *manifest, const uint64_t cf_id,
                                const char *name, const uint8_t *config_blob,
                                size_t config_blob_len);
int manifest_pending_add_cf_drop(tidesdb_manifest_t *manifest, const uint64_t cf_id);
int manifest_pending_reset(tidesdb_manifest_t *manifest);
int manifest_pending_add_record(tidesdb_manifest_t *manifest, const uint8_t op,
                                const uint64_t cf_id, const int level, const uint64_t id,
                                const uint64_t num_entries, const uint64_t size_bytes,
                                const int partition);
int manifest_apply_batch(tidesdb_manifest_t *manifest, const uint8_t *data, const size_t size);

#endif /* __MANIFEST_INTERNAL_H__ */
