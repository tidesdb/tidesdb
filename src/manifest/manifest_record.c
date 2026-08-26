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
 * manifest_pending_reserve
 * ensure the pending batch has room for need more bytes and return a write pointer to them,
 * advancing pending_len. grows the buffer by doubling
 * @return a write pointer to the reserved bytes, or NULL on allocation failure
 */
static uint8_t *manifest_pending_reserve(tidesdb_manifest_t *manifest, const size_t need)
{
    if (!manifest->pending && manifest_pending_reset(manifest) != 0) return NULL;

    if (manifest->pending_len + need > manifest->pending_cap)
    {
        size_t new_cap = manifest->pending_cap ? manifest->pending_cap : MANIFEST_BODY_INIT_CAP;
        while (new_cap < manifest->pending_len + need) new_cap *= 2;
        uint8_t *nb = realloc(manifest->pending, new_cap);
        if (!nb) return NULL;
        manifest->pending = nb;
        manifest->pending_cap = new_cap;
    }

    uint8_t *p = manifest->pending + manifest->pending_len;
    manifest->pending_len += need;
    return p;
}

/**
 * manifest_pending_add_cf_add / _cf_drop
 * append a column family registry record to the pending batch. CF_ADD is length-prefixed for its
 * variable name and its variable opaque config blob
 * @return 0 on success, -1 on allocation failure
 */
int manifest_pending_add_cf_add(tidesdb_manifest_t *manifest, const uint64_t cf_id,
                                const char *name, const uint8_t *config_blob,
                                size_t config_blob_len)
{
    const size_t name_len = strnlen(name, MANIFEST_CF_NAME_MAX - 1);
    const size_t blob_len =
        (config_blob && config_blob_len)
            ? (config_blob_len > MANIFEST_CF_BLOB_MAX ? MANIFEST_CF_BLOB_MAX : config_blob_len)
            : 0;
    uint8_t *p =
        manifest_pending_reserve(manifest, MANIFEST_REC_CF_ADD_HDR_SIZE + name_len + blob_len);
    if (!p) return -1;
    *p = MANIFEST_OP_CF_ADD;
    manifest_put_u64(p + 1, cf_id);
    manifest_put_u16(p + 9, (uint16_t)name_len);
    manifest_put_u16(p + 11, (uint16_t)blob_len);
    memcpy(p + MANIFEST_REC_CF_ADD_HDR_SIZE, name, name_len);
    if (blob_len) memcpy(p + MANIFEST_REC_CF_ADD_HDR_SIZE + name_len, config_blob, blob_len);
    return 0;
}

/**
 * manifest_pending_add_range_del
 * append a column family's whole range tombstone set to the pending batch
 * @param manifest the manifest
 * @param cf_id the family the set belongs to
 * @param blob the serialized set, or NULL with blob_len 0 to clear it
 * @param blob_len length of blob
 * @return 0 on success, -1 on allocation failure
 */
int manifest_pending_add_range_del(tidesdb_manifest_t *manifest, const uint64_t cf_id,
                                   const uint8_t *blob, const uint32_t blob_len)
{
    const uint32_t len = (blob && blob_len) ? blob_len : 0;
    uint8_t *p = manifest_pending_reserve(manifest, MANIFEST_REC_RANGE_DEL_HDR_SIZE + len);
    if (!p) return -1;
    *p = MANIFEST_OP_RANGE_DEL;
    manifest_put_u64(p + 1, cf_id);
    manifest_put_u32(p + 9, len);
    if (len) memcpy(p + MANIFEST_REC_RANGE_DEL_HDR_SIZE, blob, len);
    return 0;
}

int manifest_pending_add_cf_drop(tidesdb_manifest_t *manifest, const uint64_t cf_id)
{
    uint8_t *p = manifest_pending_reserve(manifest, MANIFEST_REC_CF_DROP_SIZE);
    if (!p) return -1;
    *p = MANIFEST_OP_CF_DROP;
    manifest_put_u64(p + 1, cf_id);
    return 0;
}

/**
 * manifest_pending_reset
 * reset the pending buffer to a fresh batch containing only the format byte. allocates the buffer
 * on first use
 * @return 0 on success, -1 on allocation failure
 */
int manifest_pending_reset(tidesdb_manifest_t *manifest)
{
    if (!manifest->pending)
    {
        manifest->pending = malloc(MANIFEST_BODY_INIT_CAP);
        if (!manifest->pending) return -1;
        manifest->pending_cap = MANIFEST_BODY_INIT_CAP;
    }
    manifest->pending[0] = (uint8_t)MANIFEST_VERSION;
    manifest->pending_len = MANIFEST_BATCH_HDR_SIZE;
    return 0;
}

/**
 * manifest_pending_add_record
 * append one fixed-size record to the pending batch. carries the owning cf id after the opcode for
 * ADD_P/MOVE/REMOVE; for MANIFEST_OP_SEQ the sequence is passed in id and cf_id is unused. grows
 * the buffer by doubling
 * @return 0 on success, -1 on allocation failure
 */
int manifest_pending_add_record(tidesdb_manifest_t *manifest, const uint8_t op,
                                const uint64_t cf_id, const int level, const uint64_t id,
                                const uint64_t num_entries, const uint64_t size_bytes,
                                const int partition)
{
    size_t need;
    switch (op)
    {
        case MANIFEST_OP_ADD_P:
            need = MANIFEST_REC_ADD_P_SIZE;
            break;
        case MANIFEST_OP_REMOVE:
            need = MANIFEST_REC_REMOVE_SIZE;
            break;
        case MANIFEST_OP_MOVE:
            need = MANIFEST_REC_MOVE_SIZE;
            break;
        case MANIFEST_OP_SEQ:
            need = MANIFEST_REC_SEQ_SIZE;
            break;
        case MANIFEST_OP_CF_SEQ:
            need = MANIFEST_REC_CF_SEQ_SIZE;
            break;
        default:
            return -1;
    }

    uint8_t *p = manifest_pending_reserve(manifest, need);
    if (!p) return -1;

    *p++ = op;
    if (op == MANIFEST_OP_SEQ || op == MANIFEST_OP_CF_SEQ)
    {
        manifest_put_u64(p, id);
        return 0;
    }

    manifest_put_u64(p, cf_id);
    p += 8;
    if (op == MANIFEST_OP_MOVE)
    {
        /* a move carries the id and its new level; the file (named by birth level) does not change
         */
        manifest_put_u64(p, id);
        p += 8;
        manifest_put_u32(p, (uint32_t)level);
        return 0;
    }

    manifest_put_u32(p, (uint32_t)level);
    p += 4;
    manifest_put_u64(p, id);
    p += 8;
    if (op == MANIFEST_OP_ADD_P)
    {
        manifest_put_u64(p, num_entries);
        p += 8;
        manifest_put_u64(p, size_bytes);
        p += 8;
        manifest_put_u32(p, (uint32_t)partition);
        p += 4;
        /* a freshly added sstable is born at this level */
        manifest_put_u32(p, (uint32_t)level);
    }
    return 0;
}

/**
 * manifest_apply_cf_record
 * apply one column-family record -- an add, a drop, or the family id high-water
 * @param manifest the set being rebuilt
 * @param data the batch payload
 * @param size the payload length
 * @param off the record's offset in the payload
 * @param out_next receives the offset just past the record
 * @return 0 on success, -1 when the record overruns the payload or is rejected
 */
static int manifest_apply_cf_record(tidesdb_manifest_t *manifest, const uint8_t *data,
                                    const size_t size, size_t off, size_t *out_next)
{
    switch (data[off])
    {
        case MANIFEST_OP_CF_ADD:
        {
            if (off + MANIFEST_REC_CF_ADD_HDR_SIZE > size) return -1;
            const uint64_t cf_id = manifest_get_u64(data + off + 1);
            const uint16_t name_len = manifest_get_u16(data + off + 9);
            const uint16_t blob_len = manifest_get_u16(data + off + 11);
            if (name_len >= MANIFEST_CF_NAME_MAX || blob_len > MANIFEST_CF_BLOB_MAX) return -1;
            if (off + MANIFEST_REC_CF_ADD_HDR_SIZE + name_len + blob_len > size) return -1;

            char name[MANIFEST_CF_NAME_MAX];
            memcpy(name, data + off + MANIFEST_REC_CF_ADD_HDR_SIZE, name_len);
            name[name_len] = '\0';
            const uint8_t *blob =
                blob_len ? data + off + MANIFEST_REC_CF_ADD_HDR_SIZE + name_len : NULL;
            if (manifest_cf_upsert_unlocked(manifest, cf_id, name, blob, blob_len) != 0) return -1;

            /* the upsert is the unlocked form, which does not raise the high-water the way the
             * public add does, so raise it here. this also floors a manifest written before the
             * high-water was recorded at the largest id it still describes */
            tidesdb_manifest_update_next_cf_id(manifest, cf_id + 1);
            *out_next = off + (size_t)(MANIFEST_REC_CF_ADD_HDR_SIZE + name_len + blob_len);
            return 0;
        }
        case MANIFEST_OP_CF_DROP:
            if (off + MANIFEST_REC_CF_DROP_SIZE > size) return -1;
            (void)manifest_cf_drop_unlocked(manifest, manifest_get_u64(data + off + 1));
            *out_next = off + MANIFEST_REC_CF_DROP_SIZE;
            return 0;
        case MANIFEST_OP_RANGE_DEL:
        {
            if (off + MANIFEST_REC_RANGE_DEL_HDR_SIZE > size) return -1;
            const uint64_t cf_id = manifest_get_u64(data + off + 1);
            const uint32_t blob_len = manifest_get_u32(data + off + 9);
            if (blob_len > MANIFEST_RANGE_DEL_BLOB_MAX) return -1;
            if (off + MANIFEST_REC_RANGE_DEL_HDR_SIZE + blob_len > size) return -1;

            const uint8_t *blob = blob_len ? data + off + MANIFEST_REC_RANGE_DEL_HDR_SIZE : NULL;
            if (manifest_range_del_upsert_unlocked(manifest, cf_id, blob, blob_len) != 0) return -1;
            *out_next = off + MANIFEST_REC_RANGE_DEL_HDR_SIZE + blob_len;
            return 0;
        }
        case MANIFEST_OP_CF_SEQ:
            if (off + MANIFEST_REC_CF_SEQ_SIZE > size) return -1;
            /* raised rather than stored, so replaying a snapshot that predates a later drop cannot
             * walk the high-water back down onto a reusable id */
            tidesdb_manifest_update_next_cf_id(manifest, manifest_get_u64(data + off + 1));
            *out_next = off + MANIFEST_REC_CF_SEQ_SIZE;
            return 0;
        default:
            return -1;
    }
}

/**
 * manifest_apply_sstable_record
 * apply one sstable record -- an add, a level move, or a removal
 * @param manifest the set being rebuilt
 * @param data the batch payload
 * @param size the payload length
 * @param off the record's offset in the payload
 * @param out_next receives the offset just past the record
 * @return 0 on success, -1 when the record overruns the payload
 */
static int manifest_apply_sstable_record(tidesdb_manifest_t *manifest, const uint8_t *data,
                                         const size_t size, size_t off, size_t *out_next)
{
    switch (data[off])
    {
        case MANIFEST_OP_ADD_P:
        {
            if (off + MANIFEST_REC_ADD_P_SIZE > size) return -1;
            const uint64_t cf_id = manifest_get_u64(data + off + 1);
            const int level = (int)manifest_get_u32(data + off + 9);
            const uint64_t id = manifest_get_u64(data + off + 13);
            const uint64_t ne = manifest_get_u64(data + off + 21);
            const uint64_t sz = manifest_get_u64(data + off + 29);
            const int partition = (int)manifest_get_u32(data + off + 37);
            const int birth_level = (int)manifest_get_u32(data + off + 41);
            tidesdb_manifest_add_sstable_unlocked(manifest, cf_id, level, id, ne, sz, partition,
                                                  birth_level);
            *out_next = off + MANIFEST_REC_ADD_P_SIZE;
            return 0;
        }
        case MANIFEST_OP_MOVE:
        {
            if (off + MANIFEST_REC_MOVE_SIZE > size) return -1;
            const uint64_t cf_id = manifest_get_u64(data + off + 1);
            const uint64_t id = manifest_get_u64(data + off + 9);
            const int new_level = (int)manifest_get_u32(data + off + 17);
            for (int i = 0; i < manifest->num_entries; i++)
            {
                if (manifest->entries[i].column_family_id == cf_id && manifest->entries[i].id == id)
                {
                    manifest->entries[i].level = new_level;
                    break;
                }
            }
            *out_next = off + MANIFEST_REC_MOVE_SIZE;
            return 0;
        }
        case MANIFEST_OP_REMOVE:
        {
            if (off + MANIFEST_REC_REMOVE_SIZE > size) return -1;
            const uint64_t cf_id = manifest_get_u64(data + off + 1);
            const int level = (int)manifest_get_u32(data + off + 9);
            const uint64_t id = manifest_get_u64(data + off + 13);
            /* the result says whether the entry was there, not whether anything went wrong; a
             * replayed remove for something already absent reaches the same set either way */
            (void)manifest_remove_entry_unlocked(manifest, cf_id, level, id);
            *out_next = off + MANIFEST_REC_REMOVE_SIZE;
            return 0;
        }
        default:
            return -1;
    }
}

/**
 * manifest_apply_batch
 * decode one committed block payload (format byte then self-delimiting records) and apply each
 * record to the in-memory set. a record whose fields would overrun the payload marks the batch
 * truncated
 * @return 0 on a clean batch, -1 if the batch was truncated (a torn final commit)
 */
int manifest_apply_batch(tidesdb_manifest_t *manifest, const uint8_t *data, const size_t size)
{
    if (size < MANIFEST_BATCH_HDR_SIZE) return -1;
    /* data[0] is the manifest version; a version that is not the current one is refused */
    if (data[0] != (uint8_t)MANIFEST_VERSION) return -1;

    size_t off = MANIFEST_BATCH_HDR_SIZE;
    while (off < size)
    {
        int rc;
        switch (data[off])
        {
            case MANIFEST_OP_CF_ADD:
            case MANIFEST_OP_CF_DROP:
            case MANIFEST_OP_CF_SEQ:
            case MANIFEST_OP_RANGE_DEL:
                rc = manifest_apply_cf_record(manifest, data, size, off, &off);
                break;
            case MANIFEST_OP_ADD_P:
            case MANIFEST_OP_MOVE:
            case MANIFEST_OP_REMOVE:
                rc = manifest_apply_sstable_record(manifest, data, size, off, &off);
                break;
            case MANIFEST_OP_SEQ:
                if (off + MANIFEST_REC_SEQ_SIZE > size) return -1;
                atomic_store(&manifest->sequence, manifest_get_u64(data + off + 1));
                off += MANIFEST_REC_SEQ_SIZE;
                rc = 0;
                break;
            default:
                return -1; /* unknown opcode -- treated as corruption */
        }
        if (rc != 0) return -1;
    }
    return 0;
}
