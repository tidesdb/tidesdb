/**
 *
 * Copyright (C) TidesDB
 *
 * Original Author: Alex Gaetano Padula
 *
 * Licensed under the Mozilla Public License, v. 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.mozilla.org/en-US/MPL/2.0/
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __MANIFEST_H__
#define __MANIFEST_H__

#define MANIFEST_INITIAL_CAPACITY 64
/* current on-disk manifest version. version 8 carries an xxhash64 checksum of the body on the
 * second line. version 7 and earlier are read as legacy without a checksum, so existing
 * databases still open and gain integrity on their next commit, which rewrites them as the
 * current version. */
#define MANIFEST_VERSION        8
#define MANIFEST_VERSION_LEGACY 7
#define MANIFEST_PATH_LEN       4096
#define MANIFEST_MAX_LINE_LEN   256
/* upper bound on a serialized body line (an int level plus three uint64 fields and separators)
 * and the initial capacity of the growable body buffer used to compute and verify the checksum */
#define MANIFEST_BODY_LINE_MAX 128
#define MANIFEST_BODY_INIT_CAP 4096
/* microseconds to wait between checks */
#define MANIFEST_CLOSE_WAIT_US 100
/* max iterations (10000 × 100μs = 1 second) */
#define MANIFEST_CLOSE_MAX_WAITS 10000

/* the manifest is an append-only block-manager log. every commit appends one
 * framed block holding a batch of these records, replayed on open to rebuild the set. a snapshot
 * batch (all live ADDs then the final SEQ) is written when the log is rolled over so replay stays
 * bounded. legacy text versions 7 and 8 are read once on open and converted forward. */
#define MANIFEST_OP_ADD       0x01
#define MANIFEST_OP_REMOVE    0x02
#define MANIFEST_OP_SEQ       0x03
#define MANIFEST_BATCH_FORMAT 1
/* on-disk record sizes (opcode byte + fields); a batch is a single format byte then self-delimiting
 * records (each record's opcode fixes its length, so no count is needed). all integers big-endian
 */
#define MANIFEST_BATCH_HDR_SIZE  1  /* u8 format */
#define MANIFEST_REC_ADD_SIZE    29 /* u8 op + i32 level + u64 id + u64 num_entries + u64 size */
#define MANIFEST_REC_REMOVE_SIZE 13 /* u8 op + i32 level + u64 id */
#define MANIFEST_REC_SEQ_SIZE    9  /* u8 op + u64 sequence */
/* roll the log over into a fresh single snapshot block when records since the last snapshot exceed
 * max(MIN_RECORDS, LIVE_MULTIPLE * live entries) -- bounds recovery replay to a small multiple of
 * the live set and amortizes the O(N) snapshot to O(1) per commit */
#define MANIFEST_ROLLOVER_MIN_RECORDS   512
#define MANIFEST_ROLLOVER_LIVE_MULTIPLE 2

#include "block_manager.h"
#include "compat.h"

/**
 * tidesdb_manifest_entry_t
 * represents a single sstable entry in the manifest
 * @param level level number (1-based)
 * @param id sstable ID
 * @param num_entries number of entries in sstable
 * @param size_bytes total size in bytes
 */
typedef struct
{
    int level;
    uint64_t id;
    uint64_t num_entries;
    uint64_t size_bytes;
} tidesdb_manifest_entry_t;

/**
 * tidesdb_manifest_t
 * in-memory representation of manifest file
 * @param entries array of sstable entries
 * @param num_entries number of entries
 * @param capacity capacity of entries array
 * @param sequence current global sequence number
 * @param path path to manifest file
 * @param bm append-only block-manager log handle. a commit appends one framed block of pending
 *           records and (durably) fdatasyncs it -- no full rewrite, no rename, no reopen. only a
 *           rollover writes a fresh file and renames it into place
 * @param pending records buffered by add/remove/update_sequence since the last commit
 * @param pending_len bytes used in the pending buffer
 * @param pending_cap allocated capacity of the pending buffer
 * @param records_since_snapshot records appended since the last snapshot; drives rollover
 * @param self_healed set when open recovered a corrupt or unreadable manifest. the recovered set
 *                    may be incomplete, so recovery must trust the on-disk sstables over this
 *                    manifest -- keep every sstable it finds and rebuild the manifest from them,
 *                    rather than deleting sstables it thinks are unreferenced
 * @param lock reader-writer lock for thread safety
 * @param active_ops count of active operations (for safe shutdown)
 */
typedef struct
{
    tidesdb_manifest_entry_t *entries;
    int num_entries;
    int capacity;
    _Atomic(uint64_t) sequence;
    char path[MANIFEST_PATH_LEN];
    block_manager_t *bm;
    uint8_t *pending;
    size_t pending_len;
    size_t pending_cap;
    int records_since_snapshot;
    int self_healed;
    pthread_rwlock_t lock;
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
 * tidesdb_manifest_add_sstable
 * adds an sstable entry to the manifest
 * @param manifest manifest to modify
 * @param level level number
 * @param id sstable ID
 * @param num_entries number of entries
 * @param size_bytes size in bytes
 * @return 0 on success, -1 on error
 */
int tidesdb_manifest_add_sstable(tidesdb_manifest_t *manifest, int level, uint64_t id,
                                 uint64_t num_entries, uint64_t size_bytes);

/**
 * tidesdb_manifest_remove_sstable
 * removes an sstable entry from the manifest
 * @param manifest manifest to modify
 * @param level level number
 * @param id sstable ID
 * @return 0 on success, -1 on error
 */
int tidesdb_manifest_remove_sstable(tidesdb_manifest_t *manifest, int level, uint64_t id);

/**
 * tidesdb_manifest_has_sstable
 * checks if manifest contains an sstable
 * @param manifest manifest to check
 * @param level level number
 * @param id sstable ID
 * @return 1 if exists, 0 if not
 */
int tidesdb_manifest_has_sstable(tidesdb_manifest_t *manifest, int level, uint64_t id);

/**
 * tidesdb_manifest_update_sequence
 * updates the global sequence number
 * @param manifest manifest to modify
 * @param sequence new sequence number
 */
void tidesdb_manifest_update_sequence(tidesdb_manifest_t *manifest, uint64_t sequence);

/**
 * tidesdb_manifest_commit
 * atomically writes the manifest to disk -- writes a temp file, renames it into place. when
 * durable_sync is set it also fsyncs the temp file before the rename and syncs the parent
 * directory after, so the commit survives a crash. with durable_sync clear (TDB_SYNC_NONE) both
 * are skipped -- the rename is still atomic, but a crash may leave a manifest whose contents or
 * directory entry never reached disk, and which can reference a not-yet-durable sstable. if path
 * differs from the manifest's currently stored path, the manifest is re-pointed to path.
 * @param manifest manifest to write
 * @param path destination path; also becomes the manifest's stored path if it differs
 * @param durable_sync non-zero to fsync the manifest + parent directory; zero to skip both
 * @return 0 on success, -1 on error
 */
int tidesdb_manifest_commit(tidesdb_manifest_t *manifest, const char *path, int durable_sync);

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