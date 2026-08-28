/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __MANIFEST_H__
#define __MANIFEST_H__

#define MANIFEST_INITIAL_CAPACITY 64
#define MANIFEST_PATH_LEN         4096
/* headroom a snapshot's temp name needs past the manifest path -- the tmp extension plus a thread
 * id and a pid, so two concurrent rollovers never pick the same name */
#define MANIFEST_TMP_SUFFIX_MAX 64
/* initial capacity of the growable pending-batch buffer */
#define MANIFEST_BODY_INIT_CAP 4096
/* microseconds to wait between checks */
#define MANIFEST_CLOSE_WAIT_US 100
/* max iterations (10000 × 100μs = 1 second) */
#define MANIFEST_CLOSE_MAX_WAITS 10000
/* upper bound on a stored column family name, mirrors TDB_MAX_CF_NAME_LEN without pulling the
 * public db header into this low-level module */
#define MANIFEST_CF_NAME_MAX 128

/* upper bound on a column family's opaque config blob. the manifest stores the blob verbatim and
 * never interprets it -- the cf_config module owns its format -- so this only has to be comfortably
 * larger than the serialized config (67 bytes today) with room to grow */
#define MANIFEST_CF_BLOB_MAX 256

/* the manifest is a db-level append-only block-manager log shared by every column family. every
 * commit appends one framed block holding a batch of these records, replayed on open to rebuild the
 * set. a snapshot batch (the cf registry, then all live ADDs, then each family's range tombstone
 * set, then the two sequence records) is written when the log is rolled over so replay stays
 * bounded. the batch format byte is the manifest version and leads every block, so a batch whose
 * version is not the current one is refused rather than misread. every record carries the column
 * family id it belongs to; a single cross-cf flush lands as one atomic block. */
#define MANIFEST_OP_REMOVE  0x02
#define MANIFEST_OP_SEQ     0x03
#define MANIFEST_OP_ADD_P   0x04 /* an sstable enters the set with its partition shard and cf */
#define MANIFEST_OP_MOVE    0x08 /* a trivial move re-points an sstable's level, keeping its file */
#define MANIFEST_OP_CF_ADD  0x09 /* a column family enters the registry with its id and name */
#define MANIFEST_OP_CF_DROP 0x0A /* a column family leaves, and its sstables die with it */
#define MANIFEST_OP_CF_SEQ \
    0x0B /* the db-global cf-id high-water, so a dropped family's id is never handed out again */
/* on-disk manifest version, written as the byte leading every batch block. v10 is a hard break with
 * no legacy reader, so a block whose leading version is not this fails replay and the manifest
 * self-heals from the on-disk sstables rather than misreading an older format */
#define MANIFEST_VERSION 10
/* partition value for a non-partitioned sstable (a flush output); a partitioned merge output
 * records its shard index instead. */
#define MANIFEST_NO_PARTITION (-1)
/* on-disk record sizes (opcode byte + fields); a batch is a single version byte then
 * self-delimiting records. every record's opcode fixes its length except CF_ADD, which is
 * length-prefixed for its variable name. all integers big-endian */
#define MANIFEST_BATCH_HDR_SIZE 1 /* u8 version */
#define MANIFEST_REC_ADD_P_SIZE                                                                  \
    45 /* u8 op + u64 cf + i32 level + u64 id + u64 num_entries + u64 size + i32 partition + i32 \
          birth_level */
#define MANIFEST_REC_MOVE_SIZE    21 /* u8 op + u64 cf + u64 id + i32 new_level */
#define MANIFEST_REC_REMOVE_SIZE  21 /* u8 op + u64 cf + i32 level + u64 id */
#define MANIFEST_REC_SEQ_SIZE     9  /* u8 op + u64 sequence (db-global, no cf) */
#define MANIFEST_REC_CF_DROP_SIZE 9  /* u8 op + u64 cf */
#define MANIFEST_REC_CF_SEQ_SIZE  9  /* u8 op + u64 next_cf_id (db-global, no cf) */
#define MANIFEST_REC_CF_ADD_HDR_SIZE \
    13 /* u8 op + u64 cf + u16 name_len + u16 blob_len, then name bytes then blob bytes */
/* roll the log over into a fresh single snapshot block when records since the last snapshot exceed
 * max(MIN_RECORDS, LIVE_MULTIPLE * live entries) -- bounds recovery replay to a small multiple of
 * the live set and amortizes the O(N) snapshot to O(1) per commit */
#define MANIFEST_ROLLOVER_MIN_RECORDS   512
#define MANIFEST_ROLLOVER_LIVE_MULTIPLE 2

#include "base/lockfree.h" /* the writer-preferring rwlock the manifest is guarded by */
#include "compat.h"
#include "io/block_manager.h"

/**
 * tidesdb_manifest_entry_t
 * a single sstable entry in the db-level manifest
 * @column_family_id the column family the sstable belongs to
 * @level current logical level (1-based), mutable by a trivial move
 * @id sstable id
 * @num_entries number of entries in the sstable
 * @size_bytes total size in bytes
 * @partition partition shard index for a partitioned merge output, or MANIFEST_NO_PARTITION for a
 *            non-partitioned flush output. it is part of the sstable's on-disk name, so anything
 *            reconstructing that name from the manifest alone needs it
 * @birth_level the level the file was created at; names the on-disk file, never changes
 */
typedef struct
{
    uint64_t column_family_id;
    int level;
    uint64_t id;
    uint64_t num_entries;
    uint64_t size_bytes;
    int partition;
    int birth_level;
} tidesdb_manifest_entry_t;

/**
 * tidesdb_manifest_cf_t
 * a column family in the manifest registry, mapping a stable id to its name and its opaque config
 * blob
 * @id stable column family id, the key every entry references
 * @name column family name, NUL-terminated
 * @config_blob the cf's serialized config, stored verbatim and never interpreted by the manifest
 * @config_blob_len length of config_blob in bytes, 0 when no config was registered
 */
typedef struct
{
    uint64_t id;
    char name[MANIFEST_CF_NAME_MAX];
    uint8_t config_blob[MANIFEST_CF_BLOB_MAX];
    uint16_t config_blob_len;
} tidesdb_manifest_cf_t;

/**
 * tidesdb_manifest_t
 * in-memory representation of the db-level manifest
 * @cfs registry of column families known to the manifest
 * @num_cfs number of column families
 * @cfs_capacity capacity of the cfs array
 * @entries array of sstable entries across all column families
 * @num_entries number of entries
 * @capacity capacity of entries array
 * @sequence current db-global sequence number
 * @next_cf_id the db-global cf-id high-water, one past the largest id ever assigned. it outlives
 * the families themselves so a dropped family's id is never reissued, which would otherwise let its
 * unreaped wal records replay into whichever family later took the id
 * @path path to manifest file
 * @bm append-only block-manager log handle. a commit appends one framed block of pending records
 * and (durably) fdatasyncs it -- no full rewrite, no rename, no reopen. only a rollover writes a
 *     fresh file and renames it into place
 * @pending records buffered by add/remove/update_sequence since the last commit
 * @pending_len bytes used in the pending buffer
 * @pending_cap allocated capacity of the pending buffer
 * @records_since_snapshot records appended since the last snapshot; drives rollover
 * @self_healed set when open discarded a corrupt or unreadable log. the set it carries is then
 *              incomplete or empty, which is why recovery readopts the sstables on disk rather
 *              than trusting it
 * @lock reader-writer lock for thread safety. writer-preferring, because the readers are the
 * engine's own background work -- a compaction asks it the level of every input file of every
 * merge -- and under sustained flush a plain rwlock never lets a writer in at all. a column family
 * create takes it exclusively twice, to name the family and to commit, so it is the writer that
 * starves
 * @active_ops count of active operations (for safe shutdown)
 */
typedef struct
{
    tidesdb_manifest_cf_t *cfs;
    int num_cfs;
    int cfs_capacity;
    tidesdb_manifest_entry_t *entries;
    int num_entries;
    int capacity;
    _Atomic(uint64_t) sequence;
    _Atomic(uint64_t) next_cf_id;
    char path[MANIFEST_PATH_LEN];
    block_manager_t *bm;
    uint8_t *pending;
    size_t pending_len;
    size_t pending_cap;
    int records_since_snapshot;
    int self_healed;
    tdb_wprwlock_t lock;
    _Atomic(int) active_ops;
} tidesdb_manifest_t;

/**
 * tidesdb_manifest_open
 * opens manifest from file, creating new if it doesn't exist
 * @param path path to manifest file
 * @return opened manifest or NULL on error
 */
tidesdb_manifest_t *tidesdb_manifest_open(const char *path);

/**
 * tidesdb_manifest_add_cf
 * registers a column family (or updates its name and config) in the manifest registry
 * @param manifest manifest to modify
 * @param cf_id stable column family id
 * @param name column family name, NUL-terminated, shorter than MANIFEST_CF_NAME_MAX
 * @param config_blob the cf's opaque serialized config, or NULL to register none
 * @param config_blob_len length of config_blob, 0 when config_blob is NULL, at most
 * MANIFEST_CF_BLOB_MAX
 * @return 0 on success, -1 on error (name too long, blob too long, allocation failure)
 */
int tidesdb_manifest_add_cf(tidesdb_manifest_t *manifest, uint64_t cf_id, const char *name,
                            const uint8_t *config_blob, size_t config_blob_len);

/**
 * tidesdb_manifest_drop_cf
 * drops a column family and every sstable that belongs to it
 * @param manifest manifest to modify
 * @param cf_id column family id
 * @return 0 on success, -1 on error
 */
int tidesdb_manifest_drop_cf(tidesdb_manifest_t *manifest, uint64_t cf_id);

/**
 * tidesdb_manifest_cf_id_by_name
 * looks up a column family's id by its name
 * @param manifest manifest to query
 * @param name column family name
 * @param out_id receives the id on a match
 * @return 0 and sets out_id on a match, -1 if no column family has that name
 */
int tidesdb_manifest_cf_id_by_name(tidesdb_manifest_t *manifest, const char *name,
                                   uint64_t *out_id);

/**
 * tidesdb_manifest_copy_cfs
 * copies the registered column families into out under the read lock
 * @param manifest manifest to read
 * @param out destination array, or NULL to query the total count
 * @param max capacity of out
 * @return number of column families copied, or the total count when out is NULL
 */
int tidesdb_manifest_copy_cfs(tidesdb_manifest_t *manifest, tidesdb_manifest_cf_t *out, int max);

/**
 * tidesdb_manifest_self_healed
 * whether open had to discard a corrupt or unreadable log and start a fresh one. the catalogue it
 * carries is then incomplete or empty, so the caller rebuilds what it can from the files on disk
 * rather than trusting it
 * @param manifest the manifest
 * @return 1 when the log was discarded at open, 0 otherwise
 */
int tidesdb_manifest_self_healed(const tidesdb_manifest_t *manifest);

/**
 * tidesdb_manifest_add_sstable
 * adds an sstable entry to the manifest under a column family
 * @param manifest manifest to modify
 * @param cf_id owning column family id
 * @param level level number
 * @param id sstable id
 * @param num_entries number of entries
 * @param size_bytes size in bytes
 * @param partition partition shard for a partitioned merge output, MANIFEST_NO_PARTITION otherwise
 * @return 0 on success, -1 on error
 */
int tidesdb_manifest_add_sstable(tidesdb_manifest_t *manifest, uint64_t cf_id, int level,
                                 uint64_t id, uint64_t num_entries, uint64_t size_bytes,
                                 int partition);

/**
 * tidesdb_manifest_remove_sstable
 * removes an sstable entry from the manifest
 * @param manifest manifest to modify
 * @param cf_id owning column family id
 * @param level level number
 * @param id sstable id
 * @return 0 on success, -1 on error
 */
int tidesdb_manifest_remove_sstable(tidesdb_manifest_t *manifest, uint64_t cf_id, int level,
                                    uint64_t id);

/**
 * tidesdb_manifest_has_sstable
 * checks if manifest contains an sstable
 * @param manifest manifest to check
 * @param cf_id owning column family id
 * @param level level number
 * @param id sstable id
 * @return 1 if exists, 0 if not
 */
int tidesdb_manifest_has_sstable(tidesdb_manifest_t *manifest, uint64_t cf_id, int level,
                                 uint64_t id);

/**
 * tidesdb_manifest_find_level_by_id
 * looks up an sstable's level by its column family and id, the source of truth for level so
 * recovery places a moved sstable at its manifest level regardless of the level encoded in its
 * filename
 * @param manifest manifest to query
 * @param cf_id owning column family id
 * @param id sstable id
 * @return the level, or -1 if the id is not in the manifest
 */
int tidesdb_manifest_find_level_by_id(tidesdb_manifest_t *manifest, uint64_t cf_id, uint64_t id);

/**
 * tidesdb_manifest_move_sstable
 * re-points an sstable to a new level without touching its file, the manifest side of a trivial
 * move. the entry's birth_level (which names the file) is preserved. the caller commits.
 * @param manifest manifest to modify
 * @param cf_id owning column family id
 * @param id sstable id
 * @param new_level the level to move the sstable to
 * @return 0 on success, -1 if the id is not present
 */
int tidesdb_manifest_move_sstable(tidesdb_manifest_t *manifest, uint64_t cf_id, uint64_t id,
                                  int new_level);

/**
 * tidesdb_manifest_copy_entries
 * copies the sstable entries belonging to one column family into out under the read lock
 * @param manifest manifest to read
 * @param cf_id the column family whose entries to select
 * @param out destination array, or NULL to query the matching count
 * @param max capacity of out; at most this many are copied even if more match
 * @return the number of entries matching cf_id, whether or not out was given
 */
int tidesdb_manifest_copy_entries(tidesdb_manifest_t *manifest, uint64_t cf_id,
                                  tidesdb_manifest_entry_t *out, int max);

/**
 * tidesdb_manifest_update_sequence
 * raise the db-global sequence high-water, which never regresses -- it seeds the next sstable id
 * on recovery, so walking it back would hand out ids that live files already carry. a value at or
 * below the current one is ignored, and the next commit persists it as a SEQ record
 * @param manifest manifest to modify
 * @param sequence the sequence to raise the high-water to
 */
void tidesdb_manifest_update_sequence(tidesdb_manifest_t *manifest, uint64_t sequence);

/**
 * tidesdb_manifest_update_next_cf_id
 * raise the db-global cf-id high-water, which never regresses, so an id belonging to a dropped
 * family is never handed out a second time. adding a family raises it on its own, so a caller only
 * needs this to seed a floor recovery derived elsewhere
 * @param manifest manifest to modify
 * @param next_cf_id one past the largest assigned id; a value at or below the current one is
 * ignored
 */
void tidesdb_manifest_update_next_cf_id(tidesdb_manifest_t *manifest, uint64_t next_cf_id);

/**
 * tidesdb_manifest_commit
 * appends the records buffered since the last commit as one framed block, closing the batch with
 * the two sequence records. when durable_sync is set the block is fsynced before the call returns,
 * so the commit survives a crash; with it clear (TDB_SYNC_NONE) the records may still be only in
 * the page cache, and a crash can leave a manifest referencing a not-yet-durable sstable. a commit
 * that pushes the log past its rollover bound goes on to rewrite it as one snapshot, and a path
 * differing from the stored one re-points the manifest and rewrites it there -- both write a temp
 * file and rename it into place
 * @param manifest manifest to write
 * @param path destination path; also becomes the manifest's stored path if it differs
 * @param durable_sync non-zero to fsync the appended block and, on a rollover, the parent directory
 * @return 0 on success, -1 on error
 */
int tidesdb_manifest_commit(tidesdb_manifest_t *manifest, const char *path, int durable_sync);

/**
 * tidesdb_manifest_hold
 * hold the log still and report the bytes it currently holds. a commit cannot append to it and a
 * rollover cannot replace it until the hold is released, which is what lets a caller copying the
 * file by name apply the length to the same bytes it measured -- a rollover renames a fresh
 * snapshot over that name, so a length measured outside the hold can describe a file that no longer
 * exists
 * @param manifest manifest to hold
 * @param out_len receives the log's length in bytes
 * @return 0 with the hold taken, -1 with no hold taken when the length could not be read
 */
int tidesdb_manifest_hold(tidesdb_manifest_t *manifest, uint64_t *out_len);

/**
 * tidesdb_manifest_release
 * release a hold taken by tidesdb_manifest_hold, letting commits and rollovers proceed
 * @param manifest manifest to release
 */
void tidesdb_manifest_release(tidesdb_manifest_t *manifest);

/**
 * tidesdb_manifest_close
 * closes manifest and frees memory. the caller must ensure no other thread is still using the
 * manifest -- it destroys the lock and frees the struct. a bounded drain waits for in-flight
 * operations as a backstop and logs to stderr if any remain, but quiescing users is the caller's
 * responsibility (tidesdb_close joins all worker threads before the owning column family frees it).
 * @param manifest manifest to close
 */
void tidesdb_manifest_close(tidesdb_manifest_t *manifest);

#endif /* __MANIFEST_H__ */
