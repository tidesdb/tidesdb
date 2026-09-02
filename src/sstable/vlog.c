/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "sstable/vlog.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/errors.h" /* TDB_SUCCESS from the encoding stage runners */
#include "base/log.h"
#include "sstable/vlog_internal.h"

/* mix a 64-bit id into a bucket hash (splitmix64 finalizer) */
static inline uint64_t vlog_hash_id(uint64_t id)
{
    id ^= id >> 30;
    id *= 0xBF58476D1CE4E5B9ULL;
    id ^= id >> 27;
    id *= 0x94D049BB133111EBULL;
    id ^= id >> 31;
    return id;
}

size_t vlog_index_locate(const vlog_t *v, uint64_t id, size_t *out_free)
{
    const size_t mask = v->bucket_cap - 1;
    size_t i = (size_t)vlog_hash_id(id) & mask;
    size_t first_free = SIZE_MAX;
    for (size_t probes = 0; probes < v->bucket_cap; probes++)
    {
        const vlog_index_entry_t *e = &v->buckets[i];
        if (e->state == VLOG_BUCKET_EMPTY)
        {
            if (first_free == SIZE_MAX) first_free = i;
            if (out_free) *out_free = first_free;
            return SIZE_MAX;
        }
        if (e->state == VLOG_BUCKET_DELETED)
        {
            if (first_free == SIZE_MAX) first_free = i;
        }
        else if (e->id == id)
        {
            if (out_free) *out_free = first_free;
            return i;
        }
        i = (i + 1) & mask;
    }
    if (out_free) *out_free = first_free;
    return SIZE_MAX;
}

/**
 * vlog_index_resize
 * grows the bucket array and reinserts live entries, dropping tombstones
 * @param v vlog handle
 * @param new_cap new power-of-two capacity
 * @return VLOG_OK or VLOG_ERR_MEMORY
 */
static int vlog_index_resize(vlog_t *v, size_t new_cap)
{
    vlog_index_entry_t *old = v->buckets;
    const size_t old_cap = v->bucket_cap;
    vlog_index_entry_t *fresh = calloc(new_cap, sizeof(*fresh));
    if (!fresh) return VLOG_ERR_MEMORY;

    v->buckets = fresh;
    v->bucket_cap = new_cap;
    v->bucket_count = 0;
    v->bucket_tomb = 0;

    for (size_t i = 0; i < old_cap; i++)
    {
        if (old[i].state != VLOG_BUCKET_OCCUPIED) continue;
        size_t slot;
        (void)vlog_index_locate(v, old[i].id, &slot);
        v->buckets[slot] = old[i];
        v->buckets[slot].state = VLOG_BUCKET_OCCUPIED;
        v->bucket_count++;
    }
    free(old);
    return VLOG_OK;
}

/**
 * vlog_chain_key
 * packs an encoding chain into one word, a codec id per byte in the order applied, so the chain a
 * value was written through can be carried and compared as a scalar
 * @param ids the codec ids
 * @param count how many, at most TDB_ENCODING_PIPELINE_MAX
 * @return the packed chain, 0 when nothing was applied
 */
static uint64_t vlog_chain_key(const uint8_t *ids, int count)
{
    uint64_t key = 0;
    if (!ids || count <= 0) return 0;
    if (count > TDB_ENCODING_PIPELINE_MAX) count = TDB_ENCODING_PIPELINE_MAX;
    for (int i = 0; i < count; i++) key |= (uint64_t)ids[i] << (i * 8);
    return key;
}

/**
 * vlog_chain_bucket
 * the accounting slot for a chain, creating it on first sight. the last slot is shared by every
 * chain past the table's size, so a store with more chains than expected under-reports their detail
 * rather than attributing their bytes to a chain that did not write them
 * @param v vlog handle, index_rw held for writing
 * @param key the packed chain
 * @return the slot index
 */
static int vlog_chain_bucket(vlog_t *v, uint64_t key)
{
    for (int i = 0; i < v->chain_n; i++)
        if (v->chain_keys[i] == key) return i;
    if (v->chain_n < VLOG_MAX_CHAINS)
    {
        v->chain_keys[v->chain_n] = key;
        return v->chain_n++;
    }
    return VLOG_MAX_CHAINS - 1;
}

void vlog_chain_account(vlog_t *v, uint64_t key, int64_t used, int64_t stored, int64_t values)
{
    const int slot = vlog_chain_bucket(v, key);
    v->chain_used[slot] = (uint64_t)((int64_t)v->chain_used[slot] + used);
    v->chain_stored[slot] = (uint64_t)((int64_t)v->chain_stored[slot] + stored);
    v->chain_values[slot] = (uint64_t)((int64_t)v->chain_values[slot] + values);
}

/**
 * vlog_index_put
 * inserts or replaces an entry, keeping the one in the higher-numbered segment when the id already
 * exists. the store never copies a value between segments -- a value leaving a mostly-dead segment
 * is rewritten by the next compaction under a fresh id -- so a duplicate id cannot arise from the
 * store's own operation. the tiebreak is defensive, resolving one deterministically in favour of
 * the later segment rather than letting the recovery scan order decide
 * @param v vlog handle
 * @param id value id
 * @param segment table slot holding the block
 * @param offset block offset within that segment
 * @param value_len uncompressed value length
 * @param disk_len framed bytes the value's block occupies
 * @param chain the packed encoding chain the value was written through
 * @return VLOG_OK or VLOG_ERR_MEMORY
 */
static int vlog_index_put(vlog_t *v, uint64_t id, uint32_t segment, uint64_t offset,
                          uint64_t value_len, uint64_t disk_len, uint64_t chain)
{
    if ((v->bucket_count + v->bucket_tomb) * VLOG_INDEX_LOAD_DEN >=
        v->bucket_cap * VLOG_INDEX_LOAD_NUM)
    {
        if (vlog_index_resize(v, v->bucket_cap * 2) != VLOG_OK) return VLOG_ERR_MEMORY;
    }

    size_t slot;
    const size_t found = vlog_index_locate(v, id, &slot);
    if (found != SIZE_MAX)
    {
        vlog_index_entry_t *e = &v->buckets[found];
        if (v->segments[segment].number > v->segments[e->segment].number)
        {
            v->used_bytes -= e->value_len;
            v->stored_bytes -= e->disk_len;
            vlog_chain_account(v, e->chain, -(int64_t)e->value_len, -(int64_t)e->disk_len, -1);
            e->segment = segment;
            e->offset = offset;
            e->value_len = value_len;
            e->disk_len = disk_len;
            e->chain = chain;
            v->used_bytes += value_len;
            v->stored_bytes += disk_len;
            vlog_chain_account(v, chain, (int64_t)value_len, (int64_t)disk_len, 1);
        }
        return VLOG_OK;
    }

    if (v->buckets[slot].state == VLOG_BUCKET_DELETED) v->bucket_tomb--;
    v->buckets[slot].id = id;
    v->buckets[slot].segment = segment;
    v->buckets[slot].offset = offset;
    v->buckets[slot].value_len = value_len;
    v->buckets[slot].disk_len = disk_len;
    v->buckets[slot].chain = chain;
    v->buckets[slot].state = VLOG_BUCKET_OCCUPIED;
    v->bucket_count++;
    v->used_bytes += value_len;
    v->stored_bytes += disk_len;
    vlog_chain_account(v, chain, (int64_t)value_len, (int64_t)disk_len, 1);
    return VLOG_OK;
}

/**
 * vlog_recover_segment
 * rebuilds index entries from one segment's blocks, skipping a torn tail or a block left
 * half-written by a crashed reclaim
 * @param v vlog handle
 * @param slot the segment's table slot
 * @param out_max_id raised to the highest id seen
 * @return VLOG_OK, VLOG_ERR_IO, or VLOG_ERR_MEMORY
 */
static int vlog_recover_segment(vlog_t *v, uint32_t slot, uint64_t *out_max_id)
{
    uint64_t fsize = 0;
    block_manager_t *bm = vlog_segment_ensure_open(v, slot);
    if (!bm || block_manager_get_size(bm, &fsize) != 0) return VLOG_ERR_IO;

    block_manager_cursor_t cur;
    if (block_manager_cursor_init_stack(&cur, bm) != 0) return VLOG_ERR_IO;

    int rc = VLOG_OK;
    while (cur.current_pos < fsize)
    {
        const uint64_t offset = cur.current_pos;
        block_manager_block_t *block = block_manager_cursor_read(&cur);
        if (!block)
        {
            if (block_manager_cursor_resync_past_hole(&cur) == 0) continue;
            if (block_manager_cursor_skip_corrupt(&cur) == 0) continue;
            break;
        }
        if (block->size >= VLOG_BLK_HDR_SIZE)
        {
            const uint64_t id = decode_uint64_le_compat(block->data);
            const uint64_t word =
                decode_uint64_le_compat((const uint8_t *)block->data + VLOG_BLK_ID_SIZE);
            const uint64_t vlen = word & VLOG_BLK_LEN_MASK;

            /* the chain is read back off the value itself, so a store reopened after its family
             * changed codec still attributes each value to what actually encoded it */
            int chain_count = (int)(word >> VLOG_BLK_CHAIN_SHIFT);
            if (chain_count > TDB_ENCODING_PIPELINE_MAX) chain_count = 0;
            if (block->size < VLOG_BLK_HDR_SIZE + (size_t)chain_count) chain_count = 0;
            const uint64_t chain =
                vlog_chain_key((const uint8_t *)block->data + VLOG_BLK_HDR_SIZE, chain_count);

            if (id > *out_max_id) *out_max_id = id;
            if (id != VLOG_ID_INVALID &&
                vlog_index_put(v, id, slot, offset, vlen,
                               block_manager_framed_size((uint32_t)block->size), chain) != VLOG_OK)
                rc = VLOG_ERR_MEMORY;
        }
        block_manager_block_free(block);
        if (rc != VLOG_OK) break;
        if (block_manager_cursor_next(&cur) != 0) break;
    }
    return rc;
}

/**
 * vlog_adopt_segments
 * opens every segment already in the store directory, ascending, and rebuilds the index from them
 * @param v vlog handle
 * @return VLOG_OK, VLOG_ERR_IO, VLOG_ERR_MEMORY, or VLOG_ERR_FULL
 */
static int vlog_adopt_segments(vlog_t *v)
{
    uint64_t *numbers = calloc(VLOG_MAX_SEGMENTS, sizeof(*numbers));
    if (!numbers) return VLOG_ERR_MEMORY;

    size_t count = 0;
    int rc = vlog_segment_scan_dir(v->dir, numbers, VLOG_MAX_SEGMENTS, &count);
    uint64_t max_id = 0;

    for (size_t i = 0; rc == VLOG_OK && i < count; i++)
    {
        uint32_t slot = 0;
        rc = vlog_segment_open(v, numbers[i], &slot);
        if (rc == VLOG_OK) rc = vlog_recover_segment(v, slot, &max_id);
    }
    free(numbers);

    if (rc == VLOG_OK) atomic_store(&v->next_id, max_id + 1);
    return rc;
}

int vlog_open(const char *dir, const vlog_config_t *config, vlog_t **out)
{
    if (!dir || !config || !out) return VLOG_ERR_INVALID;
    if (strlen(dir) >= VLOG_PATH_MAX) return VLOG_ERR_INVALID;

    vlog_t *v = calloc(1, sizeof(*v));
    if (!v) return VLOG_ERR_MEMORY;

    memcpy(v->dir, dir, strlen(dir) + 1);
    v->sync_mode = config->sync_mode;
    v->fdm = config->fdm;
    /* no builder is in flight yet, so every slot is free and nothing is protected */
    for (int i = 0; i < VLOG_MAX_BUILDERS; i++)
        atomic_store_explicit(&v->build_floors[i], VLOG_BUILD_FLOOR_NONE, memory_order_relaxed);
    v->encodings = config->encodings;
    v->segment_target_bytes = config->segment_target_bytes > 0 ? config->segment_target_bytes
                                                               : VLOG_DEFAULT_SEGMENT_TARGET_BYTES;
    atomic_init(&v->next_id, 1);
    atomic_init(&v->next_number, 0);
    atomic_init(&v->active_slot, 0);
    atomic_init(&v->seg_high, 0);
    pthread_mutex_init(&v->roll_mu, NULL);
    pthread_rwlock_init(&v->index_rw, NULL);
    v->bucket_cap = VLOG_INDEX_INITIAL_CAP;
    v->buckets = calloc(v->bucket_cap, sizeof(*v->buckets));
    if (!v->buckets)
    {
        pthread_mutex_destroy(&v->roll_mu);
        pthread_rwlock_destroy(&v->index_rw);
        free(v);
        return VLOG_ERR_MEMORY;
    }

    int rc = vlog_adopt_segments(v);
    if (rc == VLOG_OK)
    {
        /* appends land in a fresh segment rather than extending the newest recovered one, so a
         * segment sealed before a restart stays immutable across it and reclaim never has to
         * reason about a segment that grew after it was adopted */
        uint32_t slot = 0;
        rc = vlog_segment_open(v, atomic_load(&v->next_number), &slot);
        if (rc == VLOG_OK) atomic_store(&v->active_slot, slot);
    }
    if (rc != VLOG_OK)
    {
        vlog_close(v);
        return rc;
    }
    *out = v;
    return VLOG_OK;
}

void vlog_close(vlog_t *v)
{
    if (!v) return;
    const uint32_t high = atomic_load_explicit(&v->seg_high, memory_order_acquire);
    for (uint32_t i = 0; i < high && i < VLOG_MAX_SEGMENTS; i++)
    {
        if (atomic_load_explicit(&v->segments[i].state, memory_order_acquire) != VLOG_SEG_OPEN)
            continue;
        block_manager_t *closing = atomic_exchange(&v->segments[i].bm, NULL);
        if (closing)
        {
            (void)block_manager_close(closing);
            if (v->fdm) fd_manager_note_close(v->fdm, FD_LABEL_VLOG_SEGMENT);
        }
        atomic_store_explicit(&v->segments[i].state, VLOG_SEG_ABSENT, memory_order_release);
    }
    pthread_mutex_destroy(&v->roll_mu);
    pthread_rwlock_destroy(&v->index_rw);
    free(v->buckets);
    free(v);
}

/**
 * vlog_frame_payload
 * builds the block payload for a value: the vlog header, the encoding ids the value was written
 * through, then the stored bytes
 * @param v vlog handle
 * @param id the id to stamp into the header
 * @param value the value bytes
 * @param value_len uncompressed length
 * @param ids the encoding pipeline to apply, or NULL to store verbatim
 * @param id_count entries in ids; 0 stores verbatim and records no ids. a chain that cannot be
 *                 resolved or applied also stores verbatim, since the ids are recorded only when
 *                 the bytes they describe were actually produced
 * @param out_payload receives an allocated payload the caller frees
 * @param out_len receives the payload length
 * @return VLOG_OK, VLOG_ERR_MEMORY, or VLOG_ERR_INVALID when the framed block would not fit
 */
static int vlog_frame_payload(const vlog_t *v, uint64_t id, const uint8_t *value, size_t value_len,
                              const uint8_t *ids, int id_count, uint8_t **out_payload,
                              size_t *out_len)
{
    const uint8_t *stored = value;
    size_t stored_len = value_len;
    uint8_t *encoded = NULL;
    int stored_count = 0;

    if (id_count > 0 && v->encodings)
    {
        tidesdb_encoding_stage_t stages[TDB_ENCODING_PIPELINE_MAX];
        if (tidesdb_encoding_resolve(v->encodings, ids, id_count, stages,
                                     TDB_ENCODING_PIPELINE_MAX) == id_count &&
            tidesdb_encoding_stages_encode(stages, id_count, value, value_len, &encoded,
                                           &stored_len) == TDB_SUCCESS)
        {
            /* a chain that produced nothing usable -- a codec this build lacks, or a backend
             * failure -- stores the value verbatim and records no ids, rather than failing a flush
             * because a value did not compress */
            stored = encoded;
            stored_count = id_count;
        }
        else
        {
            /* the value still stores, verbatim and with no ids recorded, so this is not a failure
             * the caller sees -- but a family configured for compression silently storing plain is
             * worth knowing about */
            TDB_DEBUG_LOG(TDB_LOG_WARN,
                          "value encode failed, storing verbatim, %d stages, %zu bytes", id_count,
                          value_len);
            free(encoded);
            encoded = NULL;
            stored_len = value_len;
        }
    }

    /* a block payload length is a uint32 in the frame, so a value plus its header must fit */
    const size_t hdr = VLOG_BLK_HDR_SIZE + (size_t)stored_count;
    if (stored_len > UINT32_MAX - hdr)
    {
        free(encoded);
        return VLOG_ERR_INVALID;
    }

    const size_t payload_len = hdr + stored_len;
    uint8_t *payload = malloc(payload_len);
    if (!payload)
    {
        free(encoded);
        return VLOG_ERR_MEMORY;
    }
    encode_uint64_le_compat(payload, id);
    encode_uint64_le_compat(payload + VLOG_BLK_ID_SIZE,
                            ((uint64_t)value_len & VLOG_BLK_LEN_MASK) |
                                ((uint64_t)stored_count << VLOG_BLK_CHAIN_SHIFT));
    if (stored_count) memcpy(payload + VLOG_BLK_HDR_SIZE, ids, (size_t)stored_count);
    memcpy(payload + hdr, stored, stored_len);
    free(encoded);

    *out_payload = payload;
    *out_len = payload_len;
    return VLOG_OK;
}

int vlog_write(vlog_t *v, const uint8_t *value, size_t value_len, const uint8_t *ids,
               const int id_count, vlog_id_t *out_id, uint64_t *out_disk_bytes)
{
    if (!v || !value || value_len == 0 || !out_id) return VLOG_ERR_INVALID;

    const uint64_t id = atomic_fetch_add(&v->next_id, 1);
    uint8_t *payload = NULL;
    size_t payload_len = 0;
    int rc = vlog_frame_payload(v, id, value, value_len, ids, id_count, &payload, &payload_len);
    if (rc != VLOG_OK) return rc;

    uint32_t slot = 0;
    uint64_t offset = 0;
    const uint64_t framed = block_manager_framed_size((uint32_t)payload_len);
    rc = vlog_segment_append(v, payload, payload_len, &slot, &offset);
    if (rc == VLOG_OK)
    {
        pthread_rwlock_wrlock(&v->index_rw);
        rc = vlog_index_put(v, id, slot, offset, (uint64_t)value_len, framed,
                            vlog_chain_key(ids, id_count));
        pthread_rwlock_unlock(&v->index_rw);
    }
    free(payload);

    if (rc == VLOG_OK)
    {
        *out_id = id;
        if (out_disk_bytes) *out_disk_bytes = framed;
        atomic_fetch_add_explicit(&v->bytes_written, framed, memory_order_relaxed);
    }
    return rc;
}

/**
 * vlog_decode_value
 * turns a verified block payload into the caller's value buffer
 * @param v vlog handle
 * @param payload the block payload, its vlog header included
 * @param payload_len length of payload
 * @param value_len the uncompressed length the index recorded, used to validate the decode
 * @param out_value receives an allocated buffer the caller frees
 * @param out_len receives the value length
 * @return VLOG_OK, VLOG_ERR_CORRUPTION, or VLOG_ERR_MEMORY
 */
static int vlog_decode_value(const vlog_t *v, const uint8_t *payload, uint32_t payload_len,
                             uint64_t value_len, uint8_t **out_value, size_t *out_len)
{
    /* the chain travels with the value rather than coming from whichever sstable happens to
     * reference it, so a value decodes correctly even after a compaction has carried it forward
     * into a family whose pipeline has since changed */
    const uint64_t word = decode_uint64_le_compat(payload + VLOG_BLK_ID_SIZE);
    const int id_count = (int)(word >> VLOG_BLK_CHAIN_SHIFT);
    if (id_count < 0 || id_count > TDB_ENCODING_PIPELINE_MAX) return VLOG_ERR_CORRUPTION;
    if ((size_t)payload_len < VLOG_BLK_HDR_SIZE + (size_t)id_count) return VLOG_ERR_CORRUPTION;

    const uint8_t *ids = payload + VLOG_BLK_HDR_SIZE;
    const uint8_t *stored = ids + id_count;
    const size_t stored_len = payload_len - VLOG_BLK_HDR_SIZE - (size_t)id_count;

    if (id_count == 0)
    {
        if (stored_len != value_len) return VLOG_ERR_CORRUPTION;
        uint8_t *value = malloc(value_len ? (size_t)value_len : 1);
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

    uint8_t *plain = NULL;
    size_t dlen = 0;
    if (tidesdb_encoding_stages_decode(stages, id_count, stored, stored_len, &plain, &dlen) !=
            TDB_SUCCESS ||
        dlen != value_len)
    {
        /* the length check is the one that catches a value carried forward under one chain and read
         * back under another, since a wrong chain can still decode into the wrong number of bytes
         */
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "value decode failed, %d stages, got %zu want %zu", id_count,
                      plain ? dlen : (size_t)0, value_len);
        free(plain);
        return VLOG_ERR_CORRUPTION;
    }
    *out_value = plain;
    *out_len = dlen;
    return VLOG_OK;
}

int vlog_read(vlog_t *v, vlog_id_t id, uint8_t **out_value, size_t *out_len)
{
    if (!v || id == VLOG_ID_INVALID || !out_value || !out_len) return VLOG_ERR_INVALID;

    pthread_rwlock_rdlock(&v->index_rw);
    size_t bucket;
    const size_t found = vlog_index_locate(v, id, &bucket);
    uint64_t offset = 0, value_len = 0;
    uint32_t slot = 0;
    if (found != SIZE_MAX)
    {
        slot = v->buckets[found].segment;
        offset = v->buckets[found].offset;
        value_len = v->buckets[found].value_len;
    }
    pthread_rwlock_unlock(&v->index_rw);

    if (found == SIZE_MAX) return VLOG_ERR_NOT_FOUND;

    /* the reference is what keeps the segment's file open across the read; a reclaim draining it
     * concurrently waits for this to drop before it unlinks anything */
    if (!vlog_segment_acquire(v, slot)) return VLOG_ERR_NOT_FOUND;

    const uint32_t hint = (uint32_t)(VLOG_BLK_HDR_SIZE + value_len);
    uint32_t payload_len = 0;
    const uint8_t *payload = block_manager_borrow_block_data_at_offset(
        vlog_segment_ensure_open(v, slot), offset, hint, &payload_len);
    vlog_segment_release(v, slot);

    if (!payload) return VLOG_ERR_IO;
    if (payload_len < VLOG_BLK_HDR_SIZE || decode_uint64_le_compat(payload) != id)
        return VLOG_ERR_CORRUPTION;

    return vlog_decode_value(v, payload, payload_len, value_len, out_value, out_len);
}

int vlog_sync(vlog_t *v)
{
    if (!v) return VLOG_ERR_INVALID;
    const uint32_t high = atomic_load_explicit(&v->seg_high, memory_order_acquire);
    int rc = VLOG_OK;
    for (uint32_t i = 0; i < high && i < VLOG_MAX_SEGMENTS; i++)
    {
        if (!vlog_segment_acquire(v, i)) continue;
        block_manager_t *bm = vlog_segment_ensure_open(v, i);
        if (!bm || block_manager_escalate_fsync(bm) != 0) rc = VLOG_ERR_IO;
        vlog_segment_release(v, i);
    }
    return rc;
}

int vlog_list_segments(vlog_t *v, vlog_segment_info_t *out, size_t max, size_t *out_count)
{
    if (!v || !out || !out_count) return VLOG_ERR_INVALID;

    const uint32_t high = atomic_load_explicit(&v->seg_high, memory_order_acquire);
    size_t count = 0;
    for (uint32_t i = 0; i < high && i < VLOG_MAX_SEGMENTS; i++)
    {
        if (!vlog_segment_acquire(v, i)) continue;
        if (count >= max)
        {
            vlog_segment_release(v, i);
            return VLOG_ERR_FULL;
        }
        uint64_t size = 0;
        block_manager_t *bm = vlog_segment_ensure_open(v, i);
        const int sized = bm ? block_manager_get_size(bm, &size) : -1;
        const int named =
            vlog_segment_name(v->segments[i].number, out[count].name, sizeof(out[count].name));
        vlog_segment_release(v, i);
        if (sized != 0 || named != VLOG_OK) return VLOG_ERR_IO;
        out[count].logical_size = size;
        count++;
    }
    *out_count = count;
    return VLOG_OK;
}

int vlog_get_chain_stats(vlog_t *v, vlog_chain_stats_t *out, size_t max, size_t *out_count)
{
    if (!v || !out || !out_count) return VLOG_ERR_INVALID;
    *out_count = 0;

    pthread_rwlock_rdlock(&v->index_rw);
    for (int i = 0; i < v->chain_n && *out_count < max; i++)
    {
        vlog_chain_stats_t *e = &out[*out_count];
        memset(e, 0, sizeof(*e));

        /* unpacked back into the ids that were applied, so a caller reports the chain rather than
         * an opaque number it cannot explain */
        const uint64_t key = v->chain_keys[i];
        for (int b = 0; b < TDB_ENCODING_PIPELINE_MAX; b++)
        {
            const uint8_t id = (uint8_t)(key >> (b * 8));
            if (id == 0) break;
            e->ids[e->id_count++] = id;
        }
        e->used_bytes = v->chain_used[i];
        e->stored_bytes = v->chain_stored[i];
        e->value_count = v->chain_values[i];
        (*out_count)++;
    }
    pthread_rwlock_unlock(&v->index_rw);
    return VLOG_OK;
}

int vlog_get_stats(vlog_t *v, vlog_stats_t *out)
{
    if (!v || !out) return VLOG_ERR_INVALID;

    const uint32_t high = atomic_load_explicit(&v->seg_high, memory_order_acquire);
    uint64_t total = 0, segments = 0, live = 0, drainable = 0;
    for (uint32_t i = 0; i < high && i < VLOG_MAX_SEGMENTS; i++)
    {
        if (!vlog_segment_acquire(v, i)) continue;
        uint64_t size = 0;
        block_manager_t *bm = vlog_segment_ensure_open(v, i);
        if (bm && block_manager_get_size(bm, &size) == 0) total += size;
        if (atomic_load_explicit(&v->segments[i].draining, memory_order_relaxed)) drainable++;
        live += atomic_load_explicit(&v->segments[i].live_bytes, memory_order_relaxed);
        segments++;
        vlog_segment_release(v, i);
    }

    pthread_rwlock_rdlock(&v->index_rw);
    out->used_bytes = v->used_bytes;
    out->stored_bytes = v->stored_bytes;
    out->value_count = v->bucket_count;
    pthread_rwlock_unlock(&v->index_rw);

    out->file_size = total;
    out->dead_bytes = total > out->used_bytes ? total - out->used_bytes : 0;
    out->live_bytes = live;
    out->segment_count = segments;
    out->bytes_written = atomic_load_explicit(&v->bytes_written, memory_order_relaxed);
    out->reclaim_calls = atomic_load_explicit(&v->reclaim_calls, memory_order_relaxed);
    out->reclaim_passes = atomic_load_explicit(&v->reclaim_passes, memory_order_relaxed);
    out->segments_retired = atomic_load_explicit(&v->segments_retired, memory_order_relaxed);
    out->segments_drainable = drainable;
    return VLOG_OK;
}

uint64_t vlog_next_id(vlog_t *v)
{
    return v ? atomic_load_explicit(&v->next_id, memory_order_acquire) : 0;
}

/**
 * vlog_slot_of_number
 * finds the table slot holding a segment number
 * @param v vlog handle
 * @param number the segment number
 * @return the slot, or VLOG_MAX_SEGMENTS if no live segment carries that number
 */
static uint32_t vlog_slot_of_number(vlog_t *v, uint64_t number)
{
    const uint32_t high = atomic_load_explicit(&v->seg_high, memory_order_acquire);
    for (uint32_t i = 0; i < high && i < VLOG_MAX_SEGMENTS; i++)
    {
        if (atomic_load_explicit(&v->segments[i].state, memory_order_acquire) != VLOG_SEG_OPEN)
            continue;
        if (v->segments[i].number == number) return i;
    }
    return VLOG_MAX_SEGMENTS;
}

void vlog_live_add(vlog_t *v, uint64_t number, uint64_t bytes, uint64_t count)
{
    if (!v) return;
    const uint32_t slot = vlog_slot_of_number(v, number);
    if (slot == VLOG_MAX_SEGMENTS) return;
    atomic_fetch_add_explicit(&v->segments[slot].live_bytes, bytes, memory_order_relaxed);
    atomic_fetch_add_explicit(&v->segments[slot].live_count, count, memory_order_relaxed);
}

void vlog_live_reset(vlog_t *v)
{
    if (!v) return;
    const uint32_t high = atomic_load_explicit(&v->seg_high, memory_order_acquire);
    for (uint32_t i = 0; i < high && i < VLOG_MAX_SEGMENTS; i++)
    {
        atomic_store_explicit(&v->segments[i].live_bytes, 0, memory_order_relaxed);
        atomic_store_explicit(&v->segments[i].live_count, 0, memory_order_relaxed);
    }
}

int vlog_segment_of(vlog_t *v, vlog_id_t id, uint64_t *out_number, uint64_t *out_disk_bytes)
{
    if (!v || id == VLOG_ID_INVALID || !out_number) return VLOG_ERR_INVALID;

    pthread_rwlock_rdlock(&v->index_rw);
    const size_t bucket = vlog_index_locate(v, id, NULL);
    int rc = VLOG_ERR_NOT_FOUND;
    if (bucket != SIZE_MAX)
    {
        /* the number rather than the slot: a slot is reused as segments retire, so it would name a
         * different file by the time an sstable written now is read back */
        *out_number = v->segments[v->buckets[bucket].segment].number;
        if (out_disk_bytes) *out_disk_bytes = v->buckets[bucket].disk_len;
        rc = VLOG_OK;
    }
    pthread_rwlock_unlock(&v->index_rw);
    return rc;
}
