/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <stdlib.h>
#include <string.h>

#include "base/errors.h"
#include "base/log.h"
#include "sstable/vlog.h"
#include "sstable/vlog_internal.h"

/* reclaim must purge the index before reusing a slot. take the pin while that purge is
 * excluded so the slot and offset still name the same file when the read begins */
static int vlog_lookup_pin(vlog_t* v, vlog_id_t id, vlog_index_entry_t* out)
{
    pthread_rwlock_rdlock(&v->index_rw);
    const size_t found = vlog_index_locate(v, id, NULL);
    int rc = VLOG_ERR_NOT_FOUND;
    if (found != SIZE_MAX)
    {
        *out = v->buckets[found];
        if (vlog_segment_acquire(v, out->segment)) rc = VLOG_OK;
    }
    pthread_rwlock_unlock(&v->index_rw);
    return rc;
}

static int vlog_read_result(const int rc)
{
    if (rc == BLOCK_MANAGER_READ_ERR_CORRUPTION) return VLOG_ERR_CORRUPTION;
    return rc == BLOCK_MANAGER_READ_ERR_MEMORY ? VLOG_ERR_MEMORY : VLOG_ERR_IO;
}

static int vlog_decode_value(const vlog_t* v, const uint8_t* payload, uint32_t payload_len,
                             uint64_t value_len, uint8_t** out_value, size_t* out_len)
{
    /* the chain travels with the value rather than coming from whichever sstable happens to
     * reference it, so a value decodes correctly even after a compaction has carried it forward
     * into a family whose pipeline has since changed */
    const uint64_t word = decode_uint64_le_compat(payload + VLOG_BLK_ID_SIZE);
    const int id_count = (int)(word >> VLOG_BLK_CHAIN_SHIFT);
    if (id_count < 0 || id_count > TDB_ENCODING_PIPELINE_MAX) return VLOG_ERR_CORRUPTION;
    if ((size_t)payload_len < VLOG_BLK_HDR_SIZE + (size_t)id_count) return VLOG_ERR_CORRUPTION;

    const uint8_t* ids = payload + VLOG_BLK_HDR_SIZE;
    const uint8_t* stored = ids + id_count;
    const size_t stored_len = payload_len - VLOG_BLK_HDR_SIZE - (size_t)id_count;
    if (id_count == 0)
    {
        if (stored_len != value_len) return VLOG_ERR_CORRUPTION;
        uint8_t* value = malloc(value_len ? (size_t)value_len : 1);
        if (!value) return VLOG_ERR_MEMORY;
        memcpy(value, stored, (size_t)value_len);
        *out_value = value;
        *out_len = (size_t)value_len;
        return VLOG_OK;
    }

    /* a build without the codecs this value was written through cannot read it, which is the same
     * unreadable-stored-bytes condition as any other decode failure */
    tidesdb_encoding_stage_t stages[TDB_ENCODING_PIPELINE_MAX];
    if (!v->encodings || tidesdb_encoding_resolve(v->encodings, ids, id_count, stages,
                                                  TDB_ENCODING_PIPELINE_MAX) != id_count)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "value chain unresolved, %d ids, registry %s", id_count,
                      v->encodings ? "present" : "absent");
        return VLOG_ERR_CORRUPTION;
    }

    uint8_t* plain = NULL;
    size_t dlen = 0;
    if (tidesdb_encoding_stages_decode(stages, id_count, stored, stored_len, &plain, &dlen) !=
            TDB_SUCCESS ||
        dlen != value_len)
    {
        /* the length check is the one that catches a value carried forward under one chain and read
         * back under another, since a wrong chain can still decode into the wrong number of bytes
         */
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "value decode failed, %d stages, got %llu want %llu", id_count,
                      (unsigned long long)(plain ? dlen : (size_t)0),
                      (unsigned long long)value_len);
        free(plain);
        return VLOG_ERR_CORRUPTION;
    }
    *out_value = plain;
    *out_len = dlen;
    return VLOG_OK;
}

int vlog_read(vlog_t* v, vlog_id_t id, uint8_t** out_value, size_t* out_len)
{
    if (!v || id == VLOG_ID_INVALID || !out_value || !out_len) return VLOG_ERR_INVALID;
    vlog_index_entry_t entry;
    const int pinned = vlog_lookup_pin(v, id, &entry);
    if (pinned != VLOG_OK) return pinned;
    const uint32_t hint = (uint32_t)(VLOG_BLK_HDR_SIZE + entry.value_len);
    uint32_t payload_len = 0;
    int read = BLOCK_MANAGER_READ_ERR_IO;
    const uint8_t* payload = block_manager_borrow_block_data_at_offset_checked(
        vlog_segment_ensure_open(v, entry.segment), entry.offset, hint, &payload_len, &read);
    vlog_segment_release(v, entry.segment);
    if (!payload) return vlog_read_result(read);
    if (payload_len < VLOG_BLK_HDR_SIZE || decode_uint64_le_compat(payload) != id)
        return VLOG_ERR_CORRUPTION;
    return vlog_decode_value(v, payload, payload_len, entry.value_len, out_value, out_len);
}

static int vlog_read_range_verbatim(block_manager_t* bm, const vlog_index_entry_t* entry,
                                    size_t offset, size_t length, uint8_t** out_value,
                                    size_t* out_len)
{
    uint8_t* slice = length ? malloc(length) : NULL;
    if (length && !slice) return VLOG_ERR_MEMORY;
    uint8_t header[VLOG_BLK_HDR_SIZE];
    uint32_t payload_len = 0;
    const int rc = block_manager_read_verified_block_slices(
        bm, entry->offset, sizeof(header), header, VLOG_BLK_HDR_SIZE + (uint32_t)offset,
        (uint32_t)length, slice, &payload_len);
    if (rc != BLOCK_MANAGER_READ_OK)
    {
        free(slice);
        return vlog_read_result(rc);
    }
    const uint64_t word = decode_uint64_le_compat(header + VLOG_BLK_ID_SIZE);
    if (decode_uint64_le_compat(header) != entry->id || word != entry->value_len ||
        payload_len < VLOG_BLK_HDR_SIZE || payload_len - VLOG_BLK_HDR_SIZE != entry->value_len)
    {
        free(slice);
        return VLOG_ERR_CORRUPTION;
    }
    *out_value = slice;
    *out_len = length;
    return VLOG_OK;
}

static int vlog_read_range_encoded(vlog_t* v, block_manager_t* bm, const vlog_index_entry_t* entry,
                                   size_t offset, size_t length, uint8_t** out_value,
                                   size_t* out_len)
{
    const uint64_t framing = BLOCK_MANAGER_BLOCK_HEADER_SIZE + BLOCK_MANAGER_FOOTER_SIZE;
    if (entry->disk_len < framing + VLOG_BLK_HDR_SIZE || entry->disk_len - framing > UINT32_MAX)
        return VLOG_ERR_CORRUPTION;
    const uint32_t payload_len = (uint32_t)(entry->disk_len - framing);
    uint8_t* payload = malloc(payload_len);
    if (!payload) return VLOG_ERR_MEMORY;
    uint32_t verified_len = 0;
    const int read = block_manager_read_verified_block_slices(bm, entry->offset, 0, NULL, 0,
                                                              payload_len, payload, &verified_len);
    if (read != BLOCK_MANAGER_READ_OK)
    {
        free(payload);
        return vlog_read_result(read);
    }
    if (verified_len != payload_len)
    {
        free(payload);
        return VLOG_ERR_CORRUPTION;
    }
    const uint64_t word = decode_uint64_le_compat(payload + VLOG_BLK_ID_SIZE);
    if (decode_uint64_le_compat(payload) != entry->id ||
        (word & VLOG_BLK_LEN_MASK) != entry->value_len)
    {
        free(payload);
        return VLOG_ERR_CORRUPTION;
    }

    uint8_t* value = NULL;
    size_t decoded_len = 0;
    const int decoded =
        vlog_decode_value(v, payload, payload_len, entry->value_len, &value, &decoded_len);
    free(payload);
    if (decoded != VLOG_OK) return decoded;
    uint8_t* slice = length ? malloc(length) : NULL;
    if (length && !slice)
    {
        free(value);
        return VLOG_ERR_MEMORY;
    }
    if (length) memcpy(slice, value + offset, length);
    free(value);
    *out_value = slice;
    *out_len = length;
    return VLOG_OK;
}

int vlog_read_range(vlog_t* v, vlog_id_t id, size_t offset, size_t length, uint8_t** out_value,
                    size_t* out_len)
{
    if (!v || id == VLOG_ID_INVALID || !out_value || !out_len) return VLOG_ERR_INVALID;
    *out_value = NULL;
    *out_len = 0;
    vlog_index_entry_t entry;
    const int pinned = vlog_lookup_pin(v, id, &entry);
    if (pinned != VLOG_OK) return pinned;
    if (entry.value_len > SIZE_MAX || offset > (size_t)entry.value_len ||
        length > (size_t)entry.value_len - offset)
    {
        vlog_segment_release(v, entry.segment);
        return VLOG_ERR_RANGE;
    }

    block_manager_t* bm = vlog_segment_ensure_open(v, entry.segment);
    /* the explicit identity codec also packs to chain zero. its frame carries at least one
     * extra codec byte, distinguishing it from a verbatim record */
    const int verbatim =
        entry.chain == 0 && entry.value_len <= UINT32_MAX - VLOG_BLK_HDR_SIZE &&
        entry.disk_len == block_manager_framed_size(VLOG_BLK_HDR_SIZE + (uint32_t)entry.value_len);
    int rc = VLOG_ERR_IO;
    if (bm)
    {
        rc = verbatim ? vlog_read_range_verbatim(bm, &entry, offset, length, out_value, out_len)
                      : vlog_read_range_encoded(v, bm, &entry, offset, length, out_value, out_len);
    }
    vlog_segment_release(v, entry.segment);
    return rc;
}
