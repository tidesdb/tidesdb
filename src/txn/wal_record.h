/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_TXN_WAL_RECORD_H__
#define __TIDESDB_TXN_WAL_RECORD_H__

#include "../compat.h"
#include "base/encoding/serialization.h"

/* the write-ahead log record codec. a commit serializes its whole write set into one WAL batch that
 * the block manager frames and checksums as a single block, so a batch is all-or-nothing on disk
 * and recovery replays it entry by entry. this module is only the byte codec -- it turns an array
 * of entries into a buffer and a buffer back into entries, using the serialization module's varint
 * codec, with no block manager, no skip_list, and no engine structs. the transaction manager owns
 * writing the encoded batch to the WAL and applying decoded entries; recovery owns replaying them.
 * the batch is self-describing (a version byte, a record kind, an optional xid, then an entry
 * count) so the format can evolve and carry two-phase-commit framing. */

/* current on-disk WAL batch format version, aligned with the v10 engine release */
#define TDB_WAL_FORMAT_VERSION 10

/* WAL record kind. a single-phase commit is one WRITE_BATCH. two-phase commit splits into a PREPARE
 * (the ops plus an xid, durable but not yet committed) and a later COMMIT or ROLLBACK carrying just
 * the xid that resolves it. recovery stages a PREPARE as in-doubt until its COMMIT/ROLLBACK
 * arrives. */
#define TDB_WAL_KIND_WRITE_BATCH 0
#define TDB_WAL_KIND_PREPARE     1
#define TDB_WAL_KIND_COMMIT      2
#define TDB_WAL_KIND_ROLLBACK    3
/* a single-phase commit whose apply failed after its batch was already durable. the batch's commit
 * sequence rides in the xid slot as eight big-endian bytes -- a distinct kind rather than a
 * ROLLBACK so it can never be mistaken for a two-phase rollback, which is keyed by a caller's
 * transaction id and could legitimately be eight bytes long */
#define TDB_WAL_KIND_ABORT_SEQ 4

/* the encoded width of the sequence an abort record carries */
#define TDB_WAL_ABORT_SEQ_SIZE 8

/* per-entry flag bits */
#define TDB_WAL_ENTRY_TOMBSTONE     0x01 /* a delete; value is absent */
#define TDB_WAL_ENTRY_SINGLE_DELETE 0x02 /* the delete is a single-delete (pairs with one put) */
#define TDB_WAL_ENTRY_HAS_TTL       0x04 /* a ttl field is present for this entry */
/* the value's bytes are in the shared value log rather than in this record, which carries the id
 * they live at instead. value_size stays the value's logical length either way, so a reader knows
 * how large it is without a value log probe -- what changes is that no value bytes follow the key.
 * gated the same way the ttl field is, so a record without the bit encodes and decodes exactly as
 * it always did and the format version does not move */
#define TDB_WAL_ENTRY_VLOG_REF 0x08
/* the entry deletes every key in an interval rather than the one key it names -- one entry however
 * many keys it covers, and one that shadows keys written before it as well as keys not written yet.
 * the key is the inclusive lower bound and the value is the exclusive upper bound, empty when the
 * interval runs to the end of the column family. always set alongside TDB_WAL_ENTRY_TOMBSTONE, so a
 * reader that does not know this bit still sees a delete rather than a live put -- the value it
 * would then read as the deleted key's value is the bound, which such a reader has no use for and
 * a delete has no value field of its own to lose */
#define TDB_WAL_ENTRY_RANGE_DELETE 0x10

/**
 * tidesdb_wal_entry_t
 * one logical write in a WAL batch. on decode the key and value point into the source buffer, which
 * the caller must keep alive while the entry is in use
 * @param cf_index the target column family's prefix index
 * @param seq the commit sequence number this write carries
 * @param ttl absolute expiry time, meaningful only when TDB_WAL_ENTRY_HAS_TTL is set
 * @param flags TDB_WAL_ENTRY_* bits
 * @param key the key bytes (unprefixed)
 * @param key_size length of key
 * @param value the value bytes, NULL/0 for a tombstone and for a value held in the value log
 * @param value_size the value's logical length, whether its bytes are here or in the value log
 * @param vlog_id the value log entry holding the value, read only when the entry's flags carry
 * TDB_WAL_ENTRY_VLOG_REF, which is what makes it a reference at all
 */
typedef struct
{
    uint32_t cf_index;
    uint64_t seq;
    int64_t ttl;
    uint8_t flags;
    const uint8_t *key;
    size_t key_size;
    const uint8_t *value;
    size_t value_size;
    uint64_t vlog_id;
} tidesdb_wal_entry_t;

/**
 * tidesdb_wal_batch_size
 * the exact number of bytes tidesdb_wal_batch_encode will write, so the caller can size its buffer
 * @param kind the record kind (TDB_WAL_KIND_*)
 * @param xid the transaction id blob, or NULL for none (a single-phase WRITE_BATCH)
 * @param xid_size length of xid, 0 for none
 * @param entries the entries to be encoded (empty for a COMMIT/ROLLBACK record)
 * @param count number of entries
 * @return the encoded byte length
 */
size_t tidesdb_wal_batch_size(uint8_t kind, const uint8_t *xid, size_t xid_size,
                              const tidesdb_wal_entry_t *entries, size_t count);

/**
 * tidesdb_wal_batch_encode
 * serialize a record into out; write nothing and return 0 if out is too small or the args are
 * invalid
 * @param kind the record kind (TDB_WAL_KIND_*)
 * @param xid the transaction id blob, or NULL for none
 * @param xid_size length of xid, 0 for none
 * @param entries the entries to encode (empty for a COMMIT/ROLLBACK record)
 * @param count number of entries
 * @param out output buffer
 * @param cap capacity of out in bytes
 * @return bytes written, or 0 on failure
 */
size_t tidesdb_wal_batch_encode(uint8_t kind, const uint8_t *xid, size_t xid_size,
                                const tidesdb_wal_entry_t *entries, size_t count, uint8_t *out,
                                size_t cap);

/**
 * tidesdb_wal_cursor_t
 * a forward reader over an encoded WAL record
 * @param buf the encoded record buffer
 * @param size length of buf
 * @param pos current read offset
 * @param remaining entries not yet returned
 * @param kind the record kind (TDB_WAL_KIND_*) parsed at init
 * @param xid the transaction id blob, pointing into buf, NULL when absent
 * @param xid_size length of xid, 0 when absent
 */
typedef struct
{
    const uint8_t *buf;
    size_t size;
    size_t pos;
    size_t remaining;
    uint8_t kind;
    const uint8_t *xid;
    size_t xid_size;
} tidesdb_wal_cursor_t;

/**
 * tidesdb_wal_cursor_init
 * begin reading an encoded batch, parsing its version and entry count
 * @param c the cursor to initialize
 * @param buf the encoded batch buffer
 * @param size length of buf
 * @return 0 on success, -1 if the header is malformed or the version is unsupported
 */
int tidesdb_wal_cursor_init(tidesdb_wal_cursor_t *c, const uint8_t *buf, size_t size);

/**
 * tidesdb_wal_cursor_next
 * read the next entry, with key and value pointing into the cursor's buffer
 * @param c the cursor
 * @param out receives the next entry on success
 * @return 1 if an entry was read, 0 at the end of the batch, -1 if the batch is malformed or
 * truncated
 */
int tidesdb_wal_cursor_next(tidesdb_wal_cursor_t *c, tidesdb_wal_entry_t *out);

#endif /* __TIDESDB_TXN_WAL_RECORD_H__ */
