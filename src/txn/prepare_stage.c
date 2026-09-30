/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "prepare_stage.h"

#include <stdlib.h>
#include <string.h>

#include "base/errors.h"

/* how many record slots the map starts with and how it grows; a database rarely holds more than a
 * handful of prepared transactions at once, so this starts small and doubles */
#define TDB_PREPARE_STAGE_INIT_CAP 8

/**
 * prepare_pending_reads_t
 * the read keys a PREPARE_READS record carried, held until the PREPARE of the same xid takes them
 * @param xid the transaction id
 * @param xid_size length of xid
 * @param generation the write-ahead log generation the record was replayed from
 * @param reads the copied read keys
 * @param count how many
 */
typedef struct
{
    uint8_t *xid;
    size_t xid_size;
    uint64_t generation;
    tidesdb_wal_entry_t *reads;
    int count;
} prepare_pending_reads_t;

/**
 * tdb_prepare_stage
 * the staging map
 * @param records the staged prepares, resolved and in doubt together
 * @param count how many
 * @param capacity allocated length of records
 * @param pending read keys whose PREPARE has not been replayed yet
 * @param pending_count how many
 * @param pending_capacity allocated length of pending
 */
struct tdb_prepare_stage
{
    tdb_prepared_record_t *records;
    int count;
    int capacity;
    prepare_pending_reads_t *pending;
    int pending_count;
    int pending_capacity;
};

tdb_prepare_stage_t *tdb_prepare_stage_create(void)
{
    tdb_prepare_stage_t *stage = calloc(1, sizeof(*stage));
    if (!stage) return NULL;
    stage->records = calloc(TDB_PREPARE_STAGE_INIT_CAP, sizeof(*stage->records));
    if (!stage->records)
    {
        free(stage);
        return NULL;
    }
    stage->capacity = TDB_PREPARE_STAGE_INIT_CAP;
    return stage;
}

/* free copied entries, key and value bytes included; the decoder hands back const views, but these
 * point at the map's own copies */
static void prepare_entries_release(tidesdb_wal_entry_t *entries, const int count)
{
    for (int i = 0; i < count; i++)
    {
        free((void *)(uintptr_t)entries[i].key);
        free((void *)(uintptr_t)entries[i].value);
    }
    free(entries);
}

/* release one record's copied bytes, leaving the slot zeroed */
static void prepare_record_release(tdb_prepared_record_t *rec)
{
    prepare_entries_release(rec->entries, rec->count);
    prepare_entries_release(rec->reads, rec->read_count);
    free(rec->xid);
    memset(rec, 0, sizeof(*rec));
}

/* release one pending read set's copied bytes, leaving the slot zeroed */
static void prepare_pending_release(prepare_pending_reads_t *p)
{
    prepare_entries_release(p->reads, p->count);
    free(p->xid);
    memset(p, 0, sizeof(*p));
}

void tdb_prepare_stage_free(tdb_prepare_stage_t *stage)
{
    if (!stage) return;
    for (int i = 0; i < stage->count; i++) prepare_record_release(&stage->records[i]);
    for (int i = 0; i < stage->pending_count; i++) prepare_pending_release(&stage->pending[i]);
    free(stage->records);
    free(stage->pending);
    free(stage);
}

/* the staged record for an xid, or NULL when the map has never seen it */
static tdb_prepared_record_t *prepare_stage_find(tdb_prepare_stage_t *stage, const uint8_t *xid,
                                                 size_t xid_size)
{
    for (int i = 0; i < stage->count; i++)
        if (stage->records[i].xid_size == xid_size &&
            memcmp(stage->records[i].xid, xid, xid_size) == 0)
            return &stage->records[i];
    return NULL;
}

/* the pending read keys held for an xid, or -1 when none are */
static int prepare_pending_find(const tdb_prepare_stage_t *stage, const uint8_t *xid,
                                size_t xid_size)
{
    for (int i = 0; i < stage->pending_count; i++)
        if (stage->pending[i].xid_size == xid_size &&
            memcmp(stage->pending[i].xid, xid, xid_size) == 0)
            return i;
    return -1;
}

/* deep-copy one decoded entry, whose key and value point into a WAL block replay is about to free
 */
static int prepare_entry_copy(tidesdb_wal_entry_t *dst, const tidesdb_wal_entry_t *src)
{
    *dst = *src;
    dst->key = NULL;
    dst->value = NULL;

    if (src->key_size > 0)
    {
        uint8_t *key = malloc(src->key_size);
        if (!key) return TDB_ERR_MEMORY;
        memcpy(key, src->key, src->key_size);
        dst->key = key;
    }
    /* a referenced value carries its logical length with no bytes behind it, so the copy keys on
     * the pointer rather than the size -- taking the size at face value would read from nothing */
    if (src->value != NULL && src->value_size > 0)
    {
        uint8_t *value = malloc(src->value_size);
        if (!value) return TDB_ERR_MEMORY;
        memcpy(value, src->value, src->value_size);
        dst->value = value;
    }
    return TDB_SUCCESS;
}

/**
 * prepare_entries_copy
 * deep-copy a decoded entry array, or nothing at all when any part of it cannot be copied
 * @param src the decoded entries, pointing into a WAL block
 * @param count how many
 * @param out receives the copy, NULL when count is zero
 * @return TDB_SUCCESS, or TDB_ERR_MEMORY with nothing kept
 */
static int prepare_entries_copy(const tidesdb_wal_entry_t *src, const int count,
                                tidesdb_wal_entry_t **out)
{
    *out = NULL;
    if (count == 0) return TDB_SUCCESS;
    tidesdb_wal_entry_t *copy = calloc((size_t)count, sizeof(*copy));
    if (!copy) return TDB_ERR_MEMORY;
    for (int i = 0; i < count; i++)
    {
        if (prepare_entry_copy(&copy[i], &src[i]) != TDB_SUCCESS)
        {
            prepare_entries_release(copy, i + 1); /* including this partial entry */
            return TDB_ERR_MEMORY;
        }
    }
    *out = copy;
    return TDB_SUCCESS;
}

/* copy an xid, or NULL when it cannot be */
static uint8_t *prepare_xid_copy(const uint8_t *xid, size_t xid_size)
{
    uint8_t *copy = malloc(xid_size);
    if (copy) memcpy(copy, xid, xid_size);
    return copy;
}

/**
 * prepare_stage_hold_reads
 * hold a PREPARE_READS record's keys for the PREPARE of the same xid that follows it, replacing any
 * held already under that xid, since the newer record belongs to the newer prepare
 * @param stage the staging map
 * @param generation the generation the record was replayed from
 * @param xid the transaction id
 * @param xid_size length of xid
 * @param entries the decoded read keys, borrowed and copied here
 * @param count how many
 * @return TDB_SUCCESS, or TDB_ERR_MEMORY
 */
static int prepare_stage_hold_reads(tdb_prepare_stage_t *stage, const uint64_t generation,
                                    const uint8_t *xid, size_t xid_size,
                                    const tidesdb_wal_entry_t *entries, int count)
{
    tidesdb_wal_entry_t *reads = NULL;
    if (prepare_entries_copy(entries, count, &reads) != TDB_SUCCESS) return TDB_ERR_MEMORY;
    uint8_t *xid_copy = prepare_xid_copy(xid, xid_size);
    if (!xid_copy)
    {
        prepare_entries_release(reads, count);
        return TDB_ERR_MEMORY;
    }

    int slot = prepare_pending_find(stage, xid, xid_size);
    if (slot >= 0)
        prepare_pending_release(&stage->pending[slot]);
    else
    {
        if (stage->pending_count == stage->pending_capacity)
        {
            const int grown =
                stage->pending_capacity ? stage->pending_capacity * 2 : TDB_PREPARE_STAGE_INIT_CAP;
            prepare_pending_reads_t *pending =
                realloc(stage->pending, (size_t)grown * sizeof(*pending));
            if (!pending)
            {
                prepare_entries_release(reads, count);
                free(xid_copy);
                return TDB_ERR_MEMORY;
            }
            stage->pending = pending;
            stage->pending_capacity = grown;
        }
        slot = stage->pending_count++;
    }
    stage->pending[slot] = (prepare_pending_reads_t){xid_copy, xid_size, generation, reads, count};
    return TDB_SUCCESS;
}

/* move the read keys held for an xid into its record, if any were; the pending slot is given up */
static void prepare_stage_take_reads(tdb_prepare_stage_t *stage, tdb_prepared_record_t *rec)
{
    const int slot = prepare_pending_find(stage, rec->xid, rec->xid_size);
    if (slot < 0) return;
    prepare_pending_reads_t *p = &stage->pending[slot];
    rec->reads = p->reads;
    rec->read_count = p->count;
    if (p->generation < rec->first_generation) rec->first_generation = p->generation;
    p->reads = NULL;
    p->count = 0;
    prepare_pending_release(p);
    stage->pending[slot] = stage->pending[--stage->pending_count];
    memset(&stage->pending[stage->pending_count], 0, sizeof(*stage->pending));
}

/* stage a PREPARE, replacing any earlier record under the same xid so a reused id takes the newer
 * write set rather than resolving against a stale one */
static int prepare_stage_add(tdb_prepare_stage_t *stage, const uint64_t generation,
                             const uint8_t *xid, size_t xid_size,
                             const tidesdb_wal_entry_t *entries, int count)
{
    tdb_prepared_record_t *existing = prepare_stage_find(stage, xid, xid_size);
    if (existing) prepare_record_release(existing);

    if (!existing && stage->count == stage->capacity)
    {
        const int grown = stage->capacity * 2;
        tdb_prepared_record_t *records = realloc(stage->records, (size_t)grown * sizeof(*records));
        if (!records) return TDB_ERR_MEMORY;
        memset(records + stage->capacity, 0, (size_t)(grown - stage->capacity) * sizeof(*records));
        stage->records = records;
        stage->capacity = grown;
    }

    tdb_prepared_record_t *rec = existing ? existing : &stage->records[stage->count];
    rec->xid = prepare_xid_copy(xid, xid_size);
    if (!rec->xid) return TDB_ERR_MEMORY;
    rec->xid_size = xid_size;
    rec->resolution = TDB_PREPARE_IN_DOUBT;
    rec->count = 0;
    rec->commit_seq = 0;
    rec->generation = generation;
    rec->first_generation = generation;

    if (prepare_entries_copy(entries, count, &rec->entries) != TDB_SUCCESS)
    {
        prepare_record_release(rec);
        return TDB_ERR_MEMORY;
    }
    rec->count = count;
    for (int i = 0; i < count; i++)
        if (entries[i].seq > rec->commit_seq) rec->commit_seq = entries[i].seq;
    prepare_stage_take_reads(stage, rec);

    if (!existing) stage->count++;
    return TDB_SUCCESS;
}

int tdb_prepare_stage_observe(tdb_prepare_stage_t *stage, const uint64_t generation,
                              const uint8_t kind, const uint8_t *xid, const size_t xid_size,
                              const tidesdb_wal_entry_t *entries, const int count)
{
    if (!stage || !xid || xid_size == 0 || count < 0) return TDB_ERR_INVALID_ARGS;

    if (kind == TDB_WAL_KIND_PREPARE_READS)
        return prepare_stage_hold_reads(stage, generation, xid, xid_size, entries, count);
    if (kind == TDB_WAL_KIND_PREPARE)
        return prepare_stage_add(stage, generation, xid, xid_size, entries, count);

    if (kind != TDB_WAL_KIND_COMMIT && kind != TDB_WAL_KIND_ROLLBACK) return TDB_ERR_INVALID_ARGS;

    /* a decision for an xid the map never staged is ignored -- its PREPARE either never reached the
     * log or belongs to a generation already reclaimed, and either way there is nothing to resolve
     */
    tdb_prepared_record_t *rec = prepare_stage_find(stage, xid, xid_size);
    if (rec)
        rec->resolution =
            kind == TDB_WAL_KIND_COMMIT ? TDB_PREPARE_COMMITTED : TDB_PREPARE_ROLLEDBACK;
    return TDB_SUCCESS;
}

int tdb_prepare_stage_count(const tdb_prepare_stage_t *stage)
{
    return stage ? stage->count : 0;
}

const tdb_prepared_record_t *tdb_prepare_stage_at(const tdb_prepare_stage_t *stage, const int index)
{
    if (!stage || index < 0 || index >= stage->count) return NULL;
    return &stage->records[index];
}

uint64_t tdb_prepare_stage_max_seq(const tdb_prepare_stage_t *stage)
{
    if (!stage) return 0;
    uint64_t max_seq = 0;
    for (int i = 0; i < stage->count; i++)
        if (stage->records[i].commit_seq > max_seq) max_seq = stage->records[i].commit_seq;
    return max_seq;
}
