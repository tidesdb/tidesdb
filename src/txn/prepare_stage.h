/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_TXN_PREPARE_STAGE_H__
#define __TIDESDB_TXN_PREPARE_STAGE_H__

#include <stddef.h>
#include <stdint.h>

#include "wal_record.h"

/* the cross-generation staging map recovery resolves two-phase records against. a PREPARE carries
 * its whole entry set already sequenced, so a staged record is exactly what phase two would apply
 * and recovery never has to re-sequence anything. the map is keyed by xid and fed every two-phase
 * record in log order across every WAL generation, because a PREPARE in one generation may only be
 * resolved by a COMMIT or ROLLBACK in a later one. the keys a prepare read arrive as a record of
 * their own just ahead of its PREPARE, held until that PREPARE takes them. what is still staged
 * once the log is exhausted is in-doubt and belongs to the coordinator. the map deep-copies key and
 * value bytes, since replay frees each WAL block as soon as it has been read. */

/* how a staged transaction was resolved by a later record in the log */
#define TDB_PREPARE_IN_DOUBT  0 /* no decision seen; the coordinator must resolve it */
#define TDB_PREPARE_COMMITTED 1 /* a COMMIT record decided it; its entries must be applied */
#define TDB_PREPARE_ROLLEDBACK \
    2 /* a ROLLBACK record decided it; nothing was applied so nothing is undone */

typedef struct tdb_prepare_stage tdb_prepare_stage_t;

/**
 * tdb_prepared_record_t
 * one staged prepared transaction, owning every byte it points at
 * @param xid the transaction id the coordinator knows it by
 * @param xid_size length of xid in bytes
 * @param entries the prepared write set, already carrying the sequence phase two would apply it at
 * @param count number of entries
 * @param reads the keys the transaction read, for a prepare at repeatable read or above, so its
 *        read claims can be held again after a restart; NULL when no record of them preceded the
 *        PREPARE
 * @param read_count number of read keys
 * @param generation the write-ahead log generation the PREPARE record was replayed from, so the
 *        engine can keep exactly that log while the batch stays in doubt
 * @param first_generation the generation the batch's earliest record was replayed from, the read
 *        keys' when they came from an older log than the PREPARE, otherwise the PREPARE's own
 * @param commit_seq the sequence the whole batch commits at, taken when it prepared
 * @param resolution one of the TDB_PREPARE_* outcomes
 */
typedef struct
{
    uint8_t *xid;
    size_t xid_size;
    tidesdb_wal_entry_t *entries;
    int count;
    tidesdb_wal_entry_t *reads;
    int read_count;
    uint64_t generation;
    uint64_t first_generation;
    uint64_t commit_seq;
    int resolution;
} tdb_prepared_record_t;

/**
 * tdb_prepare_stage_create
 * create an empty staging map
 * @return the map, or NULL on allocation failure
 */
tdb_prepare_stage_t *tdb_prepare_stage_create(void);

/**
 * tdb_prepare_stage_free
 * free the map and every record, key and value it copied; safe on NULL
 * @param stage the staging map
 */
void tdb_prepare_stage_free(tdb_prepare_stage_t *stage);

/**
 * tdb_prepare_stage_observe
 * fold one two-phase WAL record into the map, recording which generation it came from. a
 * PREPARE_READS holds a deep copy of its read keys for the PREPARE of the same xid that follows; a
 * PREPARE stages a deep copy of its entries and takes the read keys held for it; a COMMIT or
 * ROLLBACK marks the matching staged record resolved. a decision naming an xid the map never saw
 * is ignored, since its PREPARE is either already applied or was never durable, and read keys no
 * PREPARE ever followed are dropped with the map
 * @param stage the staging map
 * @param generation the write-ahead log generation the record was replayed from, kept so a decision
 *                   can release exactly that log
 * @param kind the record kind, one of TDB_WAL_KIND_PREPARE_READS, _PREPARE, _COMMIT or _ROLLBACK
 * @param xid the transaction id the record carries
 * @param xid_size length of xid, must be greater than zero
 * @param entries the decoded entries, borrowed and copied here; NULL for a decision record
 * @param count number of entries, 0 for a decision record
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS on a bad record or a kind this binary does not know,
 *         or TDB_ERR_MEMORY
 */
int tdb_prepare_stage_observe(tdb_prepare_stage_t *stage, uint64_t generation, uint8_t kind,
                              const uint8_t *xid, size_t xid_size,
                              const tidesdb_wal_entry_t *entries, int count);

/**
 * tdb_prepare_stage_count
 * how many records the map holds, resolved and in-doubt together
 * @param stage the staging map
 * @return the record count, or 0 when stage is NULL
 */
int tdb_prepare_stage_count(const tdb_prepare_stage_t *stage);

/**
 * tdb_prepare_stage_at
 * borrow a staged record by index; it stays owned by the map
 * @param stage the staging map
 * @param index the record index, from 0 to tdb_prepare_stage_count minus one
 * @return the record, or NULL when the index is out of range
 */
const tdb_prepared_record_t *tdb_prepare_stage_at(const tdb_prepare_stage_t *stage, int index);

/**
 * tdb_prepare_stage_max_seq
 * the highest sequence any staged record carries, resolved or not. recovery seeds the clock past
 * this so a sequence held by a transaction that is still in-doubt is never handed out again
 * @param stage the staging map
 * @return the highest staged sequence, or 0 when the map is empty
 */
uint64_t tdb_prepare_stage_max_seq(const tdb_prepare_stage_t *stage);

#endif /* __TIDESDB_TXN_PREPARE_STAGE_H__ */
