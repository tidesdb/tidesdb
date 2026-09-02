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

struct tdb_prepare_stage
{
    tdb_prepared_record_t *records;
    int count;
    int capacity;
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

/* release one record's copied bytes, leaving the slot zeroed */
static void prepare_record_release(tdb_prepared_record_t *rec)
{
    for (int i = 0; i < rec->count; i++)
    {
        /* the decoder hands back const views, but these point at this record's own copies */
        free((void *)(uintptr_t)rec->entries[i].key);
        free((void *)(uintptr_t)rec->entries[i].value);
    }
    free(rec->entries);
    free(rec->xid);
    memset(rec, 0, sizeof(*rec));
}

void tdb_prepare_stage_free(tdb_prepare_stage_t *stage)
{
    if (!stage) return;
    for (int i = 0; i < stage->count; i++) prepare_record_release(&stage->records[i]);
    free(stage->records);
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
    rec->xid = malloc(xid_size);
    if (!rec->xid) return TDB_ERR_MEMORY;
    memcpy(rec->xid, xid, xid_size);
    rec->xid_size = xid_size;
    rec->resolution = TDB_PREPARE_IN_DOUBT;
    rec->count = 0;
    rec->commit_seq = 0;
    rec->generation = generation;

    if (count > 0)
    {
        rec->entries = calloc((size_t)count, sizeof(*rec->entries));
        if (!rec->entries)
        {
            prepare_record_release(rec);
            return TDB_ERR_MEMORY;
        }
        for (int i = 0; i < count; i++)
        {
            if (prepare_entry_copy(&rec->entries[i], &entries[i]) != TDB_SUCCESS)
            {
                rec->count = i + 1; /* release what was copied, including this partial entry */
                prepare_record_release(rec);
                return TDB_ERR_MEMORY;
            }
            if (entries[i].seq > rec->commit_seq) rec->commit_seq = entries[i].seq;
        }
        rec->count = count;
    }

    if (!existing) stage->count++;
    return TDB_SUCCESS;
}

int tdb_prepare_stage_observe(tdb_prepare_stage_t *stage, const uint64_t generation,
                              const uint8_t kind, const uint8_t *xid, const size_t xid_size,
                              const tidesdb_wal_entry_t *entries, const int count)
{
    if (!stage || !xid || xid_size == 0 || count < 0) return TDB_ERR_INVALID_ARGS;

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
