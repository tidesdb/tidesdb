/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_MEMTABLE_H__
#define __TIDESDB_MEMTABLE_H__

#include "../internal/types.h"
#include "backpressure.h"
#include "base/arena.h"           /* arena_pool_t the skip list draws node chunks from */
#include "base/waitstat.h"        /* tdb_wait_stat_t for the log-append wait */
#include "datastructures/queue.h" /* queue_t backs the l0 immutable queue */
#include "sstable/vlog.h" /* the build floor a memtable holds over values no sstable names yet */

/* the write-side in-memory state for the whole database. a memtable is a skip_list plus a
 * write-ahead log, and it is L0 for every column family on the system -- one shared memtable, never
 * one per cf. a single skip_list and a single WAL hold every cf's data, namespaced by a 4-byte
 * big-endian cf-index prefix on each key. the name -> index mapping is rebuilt from the column
 * families' own persisted state on reopen, not a sidecar file. when the active L0 memtable fills it
 * rotates into the db-level L0 queue as an immutable; a flush later dequeues each immutable and
 * writes it out to the column families' L1s. a memtable recovers from its WAL -- on open the module
 * replays each persisted WAL generation back into L0 before any read is served. the module owns
 * rotation, the L0 queue, the lock-free immutable snapshot readers walk, and the reader-pinned
 * reclamation of drained immutables. nothing above this module touches a skip_list or a
 * block_manager WAL directly. */

/**
 * tidesdb_memtable_create
 * allocate a memtable pairing -- a fresh skip_list bound to an already-open WAL block manager --
 * with its refcount at 1, no writers, and not yet flushed
 * @param wal the open write-ahead log block manager this memtable appends to
 * @param id unique identifier for this memtable
 * @param generation rotation generation counter
 * @param max_level skip_list maximum level
 * @param probability skip_list level probability
 * @param now borrowed db-wide clock the ticker publishes the current second to, which the list ages
 * entries against instead of calling time(NULL) per test, or NULL to call it directly. the sstables
 * read the same clock, and a memtable on a different one would disagree with them about a deadline
 * @param pool borrowed chunk pool the list's node arena draws from, or NULL to allocate directly
 * @return the memtable, or NULL on allocation failure (the caller keeps ownership of wal)
 */
tidesdb_memtable_t *tidesdb_memtable_create(block_manager_t *wal, uint64_t id, uint64_t generation,
                                            int max_level, float probability, _Atomic(int64_t) *now,
                                            arena_pool_t *pool);

/**
 * tidesdb_memtable_free
 * free a memtable pairing, freeing its skip_list; the WAL is not closed here since its lifetime is
 * managed by the flush path (which closes and may unlink it once the immutable is durable)
 * @param mt the memtable to free, may be NULL
 */
void tidesdb_memtable_free(tidesdb_memtable_t *mt);

/* digits in a WAL file name, zero-padded; a WAL is named by its generation alone, matching the
 * sstable klog convention (globally identifiable, no legacy prefix) */
#define TDB_WAL_ID_DIGITS 7

/* column-family indices tracked for the per-cf unflushed-key counter; a family whose dense index
 * lands past this table simply reports no unflushed count, so the bound stays a stats-only cap */
#define TDB_L0_MAX_TRACKED_CFS 1024

/* abandoned commit sequences remembered at once. one entry costs a failed apply of an already
 * durable batch, which needs an allocation failure or a lost pin retried a hundred times, so a
 * database that fills this has problems this table is not the answer to */
#define TDB_L0_MAX_ABORTED_SEQS 64

/**
 * tidesdb_wal_filename
 * format the on-disk WAL file name for a memtable generation, NNNNNNN.log, so the engine mints one
 * per rotation and rediscovers them in order on open
 * @param generation the memtable generation naming the file
 * @param out the buffer to write the NUL-terminated name into
 * @param out_size the buffer capacity
 * @return TDB_SUCCESS, or TDB_ERR_INVALID_ARGS on a bad argument or a buffer too small
 */
int tidesdb_wal_filename(uint64_t generation, char *out, size_t out_size);

/**
 * tidesdb_wal_flushed_filename
 * the name a generation's log takes once its memtable is flushed and the file is kept only for an
 * undecided prepare, so recovery replays the two-phase records in it and not the data ones
 * @param generation the memtable generation naming the file
 * @param out receives the name
 * @param out_size capacity of out
 * @return TDB_SUCCESS, or TDB_ERR_INVALID_ARGS when the name would not fit
 */
int tidesdb_wal_flushed_filename(uint64_t generation, char *out, size_t out_size);

/* ===== the shared L0 subsystem ===== */

/**
 * tidesdb_l0_t
 * the one shared L0 for the whole database -- the active memtable slot plus the db-level queue of
 * rotated immutables awaiting flush, the cf-index prefix allocator, and the pluggable write
 * backpressure. there is exactly one of these per db; L0 is never per column family.
 * @param write_buffer_size db-level rotation threshold in bytes for the active L0 memtable
 * @param l0_queue_size db-level peak L0 queue depth at which writers block; <= 0 is unbounded
 * @param max_level skip_list max level for memtables this subsystem creates
 * @param probability skip_list level probability for memtables this subsystem creates
 * @param active the active L0 memtable, the one writes land in until it rotates
 * @param active_readers reader epoch guarding the active slot so a rotation cannot free a memtable
 * a reader or writer has just loaded from it
 * @param queue the L0 queue of rotated immutable memtables awaiting flush
 * @param visible_changes count of changes to the reader-visible set -- both the active-to-immutable
 * swap and the retirement of a flushed immutable -- so a read that spans the active and the queue
 * non-atomically can tell the set moved under it and retry rather than report a false absence
 * @param next_cf_index next cf prefix index to hand out, raised past every index seen on reopen
 * @param wal_ack_on_stage non-zero to let a WAL append return once its record is staged in the
 * ring, rather than once the flush thread has carried it to the file; the weakest durability mode
 * sets it, every other mode leaves it clear
 * @param backpressure pluggable write-admission policy consulted as the L0 queue fills
 * @param flushes_in_flight immutables claimed by a flush worker but not yet retired, reported to
 * the backpressure policy so it can tell a draining queue from a stuck one
 * @param tier_depth the deepest flush tier across the families, published by the compaction
 * scheduler. the queue beside it says whether flush keeps up; this says whether merging does
 * @param admits_throttled writers the policy made dwell before admitting
 * @param admits_blocked writers the policy made wait for the queue to drain
 * @param admit_stall_us total microseconds writers were held in admission, dwell plus wait
 * @param admit_ceiling_hits writers admitted only because the wait ceiling expired, each one a
 * flush that is not keeping up
 * @param admit_max_us the longest single admission wait, which is what a latency tail is made of
 * @param wal_wait how long appends have been made to wait on the log
 * @param cf_unflushed per-cf-index pointers to each column family's unflushed distinct-key counter,
 * bound by the owner so an apply can attribute a newly resident key to its family without the l0
 * knowing about column families; a cf index past the table is simply not tracked
 * @param aborted_seqs commit sequences whose batch was applied in part and then abandoned, because
 * the apply failed after the log write had already made the batch durable. a read and a flush both
 * skip a version carrying one of these, so entries the failed commit left behind are never visible
 * and never reach L1
 * @param aborted_count how many are held
 * @param aborted_lock guards additions; readers take the count with an acquire load and walk
 * without it, which is safe because entries are only ever appended
 * @param pending_reclaim immutables whose readers had not left when the flush finished with them,
 * held here for a later sweep rather than waited on inline
 */
typedef struct
{
    size_t write_buffer_size;
    int l0_queue_size;
    int max_level;
    float probability;
    _Atomic(tidesdb_memtable_t *) active;
    tdb_epoch_t active_readers;
    queue_t *queue;
    _Atomic(uint64_t) visible_changes;
    _Atomic(uint32_t) next_cf_index;
    int wal_ack_on_stage;
    tidesdb_backpressure_t *backpressure;
    _Atomic(int) flushes_in_flight;
    /* the deepest flush tier across the families, published by the compaction scheduler. the queue
     * beside it says whether flush keeps up; this says whether merging does */
    _Atomic(int) tier_depth;
    _Atomic(uint64_t) admits_throttled;
    _Atomic(uint64_t) admits_blocked;
    _Atomic(uint64_t) admit_stall_us;
    _Atomic(uint64_t) admit_ceiling_hits;
    _Atomic(uint64_t) admit_max_us;
    /* framed bytes handed to the log, counted where the append happens. the log is one shared
     * structure for every family, so this belongs here rather than beside a family's counters,
     * and it is what the device was asked to write rather than what an entry encoded to */
    _Atomic(uint64_t) wal_bytes_written;
    tdb_wait_stat_t wal_wait;
    /* the shared value log, borrowed, for the floor a memtable holds over values only it names */
    vlog_t *vlog;
    _Atomic(_Atomic(int64_t) *) cf_unflushed[TDB_L0_MAX_TRACKED_CFS];
    uint64_t aborted_seqs[TDB_L0_MAX_ABORTED_SEQS];
    _Atomic(int) aborted_count;
    pthread_mutex_t aborted_lock;
    _Atomic(void *) pending_reclaim;
    /* a writer held by backpressure waits here rather than waking on a timer. the backlog it waits
     * on is drained by another thread, so that thread can say when to look again -- and polling it
     * instead costs a wakeup every couple of hundred microseconds per blocked writer, which on a
     * machine with fewer cores than it has blocked writers is the scheduler's whole budget spent
     * on threads discovering nothing has changed */
    pthread_mutex_t admit_mtx;
    pthread_cond_t admit_cv;
} tidesdb_l0_t;

/**
 * tidesdb_l0_create
 * create the shared L0 subsystem with an empty queue and its cf-index allocator at zero; a NULL
 * backpressure policy installs the default graduated policy
 * @param write_buffer_size db-level rotation threshold in bytes for the active L0 memtable
 * @param l0_queue_size db-level peak L0 queue depth for backpressure; <= 0 is unbounded
 * @param max_level skip_list max level for memtables the subsystem creates
 * @param probability skip_list level probability for memtables the subsystem creates
 * @param policy backpressure decision policy, or NULL for the default
 * @param policy_ctx opaque context passed to the policy
 * @return the subsystem, or NULL on allocation failure
 */
tidesdb_l0_t *tidesdb_l0_create(size_t write_buffer_size, int l0_queue_size, int max_level,
                                float probability, tidesdb_backpressure_policy_fn policy,
                                void *policy_ctx);

/**
 * tidesdb_l0_destroy
 * free the shared L0 subsystem, its queue, and its backpressure controller; any memtables still in
 * the queue are the caller's responsibility to drain first
 * @param l0 the subsystem, may be NULL
 */
void tidesdb_l0_destroy(tidesdb_l0_t *l0);

/**
 * tidesdb_l0_cf_index_alloc
 * hand out the next unused cf prefix index for a newly created column family
 * @param l0 the subsystem
 * @return the allocated 4-byte cf-index
 */
uint32_t tidesdb_l0_cf_index_alloc(tidesdb_l0_t *l0);

/**
 * tidesdb_l0_cf_index_observe
 * account for a cf-index recovered from a column family's manifest on reopen so the allocator never
 * hands out an index already in use; raises the next index to at least seen + 1
 * @param l0 the subsystem
 * @param seen a cf-index read back from a manifest during reconstruction
 */
void tidesdb_l0_cf_index_observe(tidesdb_l0_t *l0, uint32_t seen);

/**
 * tidesdb_l0_bind_cf_counter
 * bind a column family's unflushed distinct-key counter at its cf index, so a later apply that
 * lands a new resident key increments it; pass NULL to unbind when the family is dropped. an index
 * past the tracked table is ignored, leaving that family's stat at zero
 * @param l0 the subsystem
 * @param cf_index the column family's prefix index
 * @param counter the family's counter, or NULL to unbind
 */
void tidesdb_l0_bind_cf_counter(tidesdb_l0_t *l0, uint32_t cf_index, _Atomic(int64_t) *counter);

/**
 * tidesdb_l0_set_active
 * install the active L0 memtable, returning the memtable previously in the slot (NULL on the first
 * install); used at open and recovery to seed L0 before any write. the subsystem takes over the
 * caller's reference to mt, and the returned old memtable's reference passes back to the caller
 * @param l0 the subsystem
 * @param mt the memtable to make active, with an open WAL; must be non-NULL
 * @return the memtable previously active, or NULL if the slot was empty
 */
tidesdb_memtable_t *tidesdb_l0_set_active(tidesdb_l0_t *l0, tidesdb_memtable_t *mt);

/**
 * tidesdb_l0_put
 * write one key-value into L0 -- append it to the active memtable's WAL, then apply it to the
 * active skip_list under the shared cf-index prefix, so the record is durable before it is visible.
 * the key is namespaced by cf_index; the same key under two column families is two distinct L0
 * entries
 * @param l0 the subsystem
 * @param cf_index the column family's prefix index
 * @param key the caller's key bytes (unprefixed)
 * @param key_size length of key
 * @param value the value bytes, may be NULL only when flags marks a tombstone
 * @param value_size length of value
 * @param ttl absolute expiry time, or -1 for none
 * @param seq the MVCC sequence number for this write
 * @param flags skip_list flags -- 0 for a live put, SKIP_LIST_FLAG_DELETED for a tombstone
 * @return TDB_SUCCESS, TDB_ERR_BUSY if the active slot could not be pinned, or an IO/memory error
 */
int tidesdb_l0_put(tidesdb_l0_t *l0, uint32_t cf_index, const uint8_t *key, size_t key_size,
                   const uint8_t *value, size_t value_size, int64_t ttl, uint64_t seq,
                   uint8_t flags);

/**
 * tidesdb_l0_get
 * read L0 for a key under cf_index -- the active memtable first, then the immutable queue newest to
 * oldest, each pinned against rotation and reclamation. the first hit is the newest version, since
 * a memtable rotated later holds strictly newer writes than any before it
 * @param l0 the subsystem
 * @param cf_index the column family's prefix index
 * @param key the caller's key bytes (unprefixed)
 * @param key_size length of key
 * @param value out, receives a malloc'd copy of the value on a live hit (caller frees)
 * @param value_size out, receives the value length on a hit
 * @param ttl out, receives the entry ttl on a hit
 * @param deleted out, set to 1 when the hit is a tombstone
 * @return TDB_SUCCESS on a hit (live or tombstone), TDB_ERR_NOT_FOUND if absent, TDB_ERR_BUSY if
 * the active slot could not be pinned, or TDB_ERR_INVALID_ARGS when the hit's value lives in the
 * value log, which this entry point cannot report -- read through tidesdb_l0_get_at_seq instead
 */
int tidesdb_l0_get(tidesdb_l0_t *l0, uint32_t cf_index, const uint8_t *key, size_t key_size,
                   uint8_t **value, size_t *value_size, int64_t *ttl, uint8_t *deleted);

/**
 * tidesdb_l0_get_at_seq
 * read L0 for the newest version of a key under cf_index visible at a snapshot sequence -- the
 * highest seq at or below snapshot across the active memtable and the immutables, newest first. the
 * snapshot ceiling is not the only filter: a commit whose apply failed can leave entries at a
 * sequence that never committed, and those are stepped over in favour of an older visible version
 * @param l0 the subsystem
 * @param cf_index the column family's prefix index
 * @param key the caller's key bytes (unprefixed)
 * @param key_size length of key
 * @param snapshot the reader's snapshot sequence, or UINT64_MAX for the latest version
 * @param value out, receives a malloc'd copy of the value on a live inline hit (caller frees), and
 * NULL when the hit's bytes live in the value log
 * @param value_size out, receives the value's logical length on a hit, whether its bytes are here
 * or in the value log
 * @param vlog_id out, receives the value log entry holding the bytes, or 0 when they are inline;
 * may be NULL only where the caller has established L0 holds no references
 * @param ttl out, receives the entry ttl on a hit
 * @param deleted out, set to 1 when the hit is a tombstone
 * @param seq out, receives the resolved version's sequence on a hit
 * @return TDB_SUCCESS on a hit, TDB_ERR_NOT_FOUND if absent, TDB_ERR_BUSY if the active slot could
 * not be pinned
 */
int tidesdb_l0_get_at_seq(tidesdb_l0_t *l0, uint32_t cf_index, const uint8_t *key, size_t key_size,
                          uint64_t snapshot, uint8_t **value, size_t *value_size, uint64_t *vlog_id,
                          int64_t *ttl, uint8_t *deleted, uint64_t *seq);

/**
 * tidesdb_l0_apply
 * make one committed write visible in the active memtable's skip_list without touching the WAL; the
 * commit's durable WAL batch was already appended by tidesdb_l0_wal_append_one. this is the apply
 * half of the transaction commit backend
 * @param l0 the subsystem
 * @param cf_index the column family's prefix index
 * @param key the caller's key bytes (unprefixed)
 * @param key_size length of key
 * @param value the value bytes, may be NULL only when flags marks a tombstone
 * @param value_size length of value
 * @param ttl absolute expiry time, or -1 for none
 * @param seq the MVCC commit sequence for this write
 * @param flags skip_list flags -- 0 for a live put, SKIP_LIST_FLAG_DELETED for a tombstone
 * @return TDB_SUCCESS, TDB_ERR_BUSY if the active slot could not be pinned, or a memory error
 */
int tidesdb_l0_apply(tidesdb_l0_t *l0, uint32_t cf_index, const uint8_t *key, size_t key_size,
                     const uint8_t *value, size_t value_size, int64_t ttl, uint64_t seq,
                     uint8_t flags);

/**
 * tidesdb_l0_apply_range_tombstone
 * make one committed range delete visible in the active memtable, covering every key in [lo, hi)
 * in its column family from this sequence on. it is one entry however many keys it covers, and it
 * shadows keys already written as well as keys not written yet, so it is not the same thing as
 * deleting the keys that happen to be there. the apply half of a commit that deleted a range, the
 * WAL batch already appended by the backend
 * @param l0 the subsystem
 * @param cf_index the column family's prefix index
 * @param lo the caller's inclusive lower bound (unprefixed), which must not be empty
 * @param lo_size length of lo, which must be greater than zero
 * @param hi the caller's exclusive upper bound (unprefixed), or NULL with hi_size 0 to run to the
 * end of the family
 * @param hi_size length of hi, 0 for the end of the family
 * @param seq the MVCC commit sequence for this delete
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_BUSY if the active slot could not be pinned,
 *         or TDB_ERR_MEMORY
 */
int tidesdb_l0_apply_range_tombstone(tidesdb_l0_t *l0, uint32_t cf_index, const uint8_t *lo,
                                     size_t lo_size, const uint8_t *hi, size_t hi_size,
                                     uint64_t seq);

/**
 * tidesdb_memtable_range_tombstone_covering
 * the newest range tombstone in one memtable covering a prefixed key at or below the snapshot,
 * stepping over one an abandoned commit left behind. a scan consults this per memtable so a delete
 * still sitting in L0 hides the keys it covers wherever those keys came from
 * @param l0 the subsystem, for the abandoned-commit set
 * @param mt the memtable to ask
 * @param pkey the key with its column family prefix, the form the shared skip list sorts on
 * @param pkey_size length of pkey in bytes
 * @param snapshot the reader's ceiling, inclusive
 * @param out_seq receives the covering sequence when the call returns 1
 * @return 1 when a tombstone at or below the snapshot covers the key, 0 otherwise
 */
int tidesdb_memtable_range_tombstone_covering(const tidesdb_l0_t *l0, tidesdb_memtable_t *mt,
                                              const uint8_t *pkey, size_t pkey_size,
                                              uint64_t snapshot, uint64_t *out_seq);

/**
 * tidesdb_l0_range_has_newer
 * whether L0 holds any key in [lo, hi) at a sequence above seq_floor -- what a commit asks on
 * behalf of a prefix delete, which writes an interval and so has no one key to probe. the walk
 * stops at the first one it finds, since that is all the commit needs to know
 * @param l0 the subsystem
 * @param cf_index the column family's prefix index
 * @param lo inclusive lower bound (unprefixed)
 * @param lo_size length of lo
 * @param hi exclusive upper bound (unprefixed), or NULL with hi_size 0 to run to the end of the
 * family
 * @param hi_size length of hi, 0 for the end of the family
 * @param seq_floor the sequence a version must exceed to count as newer
 * @param newer out, set non-zero as soon as one is found
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_MEMORY, or TDB_ERR_BUSY when the probe could
 *         not see all of L0 and so cannot clear the commit
 */
int tidesdb_l0_range_has_newer(tidesdb_l0_t *l0, uint32_t cf_index, const uint8_t *lo,
                               size_t lo_size, const uint8_t *hi, size_t hi_size,
                               uint64_t seq_floor, int *newer);

/**
 * tidesdb_l0_set_vlog
 * give the subsystem the shared value log, so a memtable receiving a reference can hold a floor
 * over the segment its bytes live in until its flush installs. set once before any write, and left
 * NULL by a caller whose commits never separate a value
 * @param l0 the subsystem
 * @param vlog the shared value log, borrowed
 */
void tidesdb_l0_set_vlog(tidesdb_l0_t *l0, vlog_t *vlog);

/**
 * tidesdb_l0_apply_reference
 * make one committed write visible whose value was already appended to the shared value log, so
 * the memtable holds the id and the logical length rather than the bytes. the apply half of a
 * commit that separated the value, and otherwise identical to tidesdb_l0_apply
 * @param l0 the subsystem
 * @param cf_index the column family's prefix index
 * @param key the caller's key bytes (unprefixed)
 * @param key_size length of key
 * @param vlog_id the value log entry holding the bytes, must be non-zero
 * @param value_size the value's logical length
 * @param ttl absolute expiry time, or -1 for none
 * @param seq the MVCC commit sequence for this write
 * @param flags skip_list flags; a tombstone references nothing, so SKIP_LIST_FLAG_DELETED is
 * rejected
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_BUSY if the active slot could not be pinned,
 * or a memory error
 */
int tidesdb_l0_apply_reference(tidesdb_l0_t *l0, uint32_t cf_index, const uint8_t *key,
                               size_t key_size, uint64_t vlog_id, size_t value_size, int64_t ttl,
                               uint64_t seq, uint8_t flags);

/**
 * tidesdb_l0_set_wal_ack_on_stage
 * choose where a WAL append stops waiting, before any writer exists. clear, the default, waits for
 * the flush thread to carry the record out of the ring, so an acknowledged commit has left process
 * memory. set, the append returns once the record is staged, so an acknowledged commit can be lost
 * to a crash of this process; only the weakest durability mode asks for that
 * @param l0 the subsystem
 * @param ack_on_stage non-zero to acknowledge on staging
 */
void tidesdb_l0_set_wal_ack_on_stage(tidesdb_l0_t *l0, int ack_on_stage);

/**
 * tidesdb_l0_sync_active_wal
 * force the active memtable's write-ahead log to the device, under the same pin an append takes.
 * the pin is what keeps the log open for the duration -- a rotation may seal the memtable
 * meanwhile, but a flush drains the writers epoch before it closes the log, so the descriptor
 * cannot go away mid-sync. it deliberately takes no rotation lock: that lock is on the commit path,
 * and holding it across an fsync stalls every committer in the database for the length of the
 * device barrier
 * @param l0 the subsystem
 * @return TDB_SUCCESS including when the active memtable has no log, TDB_ERR_INVALID_ARGS,
 * TDB_ERR_BUSY if the active slot could not be pinned, or TDB_ERR_IO if the sync failed
 */
int tidesdb_l0_sync_active_wal(tidesdb_l0_t *l0);

/**
 * tidesdb_l0_wal_append_one
 * append one pre-framed commit batch to the active memtable's WAL under a pin. concurrent
 * committers each stage their own record into the WAL's append ring, so they coalesce on the ring's
 * single reserving atomic and on the flush thread that writes whatever completed as one run, rather
 * than on a leader that does every append itself while the rest of the group waits for it. whether
 * this returns at the ring or at the file is tidesdb_l0_set_wal_ack_on_stage's to decide; either
 * way the ring's own reservation still blocks on a slot whose bytes have not been written, so
 * staging cannot outrun the flush thread without bound
 * @param l0 the subsystem
 * @param batch the framed batch bytes
 * @param size the length of batch, must be positive
 * @return TDB_SUCCESS, TDB_ERR_BUSY if the active slot could not be pinned, TDB_ERR_INVALID_ARGS,
 * or TDB_ERR_IO on a write failure
 */
int tidesdb_l0_wal_append_one(tidesdb_l0_t *l0, const uint8_t *batch, size_t size);

/* ===== rotation, the immutable queue, and reclamation ===== */

/**
 * tidesdb_l0_rotate
 * seal the active memtable and install a caller-minted replacement -- swap new_mt into the active
 * slot and enqueue the sealed one at the back of the immutable queue for a later flush. the caller
 * mints new_mt (a fresh skip_list bound to a fresh open WAL) so this module never creates WAL
 * files, keeping it unit-testable. must not be called concurrently with itself. the queue takes
 * over the sealed memtable's structural reference; new_mt's reference passes to the active slot.
 * @param l0 the subsystem
 * @param new_mt the fresh active memtable, with an open WAL and no writes yet; must be non-NULL
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, or TDB_ERR_MEMORY if the enqueue allocation failed
 * (the sealed memtable's data stays durable in its WAL and is recovered on reopen)
 */
int tidesdb_l0_rotate(tidesdb_l0_t *l0, tidesdb_memtable_t *new_mt);

/**
 * tidesdb_l0_active_full
 * report whether the active memtable has reached the db-level rotation threshold; the caller mints
 * a replacement and calls tidesdb_l0_rotate when it has. a zero write_buffer_size never fills.
 * @param l0 the subsystem
 * @return 1 when the active memtable's byte size is at or above write_buffer_size, 0 otherwise
 */
int tidesdb_l0_active_full(tidesdb_l0_t *l0);

/**
 * tidesdb_l0_dequeue_immutable
 * remove and return the oldest immutable memtable for flushing, transferring its structural
 * reference to the caller; the flush later marks it flushed and reclaims it
 * @param l0 the subsystem
 * @return the oldest queued immutable, or NULL when the queue is empty
 */
tidesdb_memtable_t *tidesdb_l0_dequeue_immutable(tidesdb_l0_t *l0);

/**
 * tidesdb_l0_admit_wake
 * wake every writer parked by backpressure so each re-decides against the current backlog
 *
 * called by whichever thread made the backlog shallower, since it is the only one that knows. a
 * writer parks rather than polling, so without this it waits out its fallback interval for a
 * change that already happened
 * @param l0 the subsystem, may be NULL
 */
void tidesdb_l0_admit_wake(tidesdb_l0_t *l0);

/**
 * tidesdb_l0_claim_immutable
 * claim the oldest not-yet-claimed immutable for flushing WITHOUT removing it from the queue, so it
 * stays reader-visible until it is retired after its data reaches L1 -- this is what closes the
 * flush visibility gap. concurrent workers claim distinct immutables. the caller flushes it and
 * then calls tidesdb_l0_retire_immutable
 * @param l0 the subsystem
 * @return the claimed immutable, still queued, or NULL when none is unclaimed or the queue is empty
 */
tidesdb_memtable_t *tidesdb_l0_claim_immutable(tidesdb_l0_t *l0);

/**
 * tidesdb_l0_retire_immutable
 * remove a claimed immutable from the queue and reclaim it, once its data is durable in L1; a no-op
 * on the queue when the immutable was taken with tidesdb_l0_dequeue_immutable instead of claimed
 * @param l0 the subsystem
 * @param mt the immutable to retire, may be NULL
 */
void tidesdb_l0_retire_immutable(tidesdb_l0_t *l0, tidesdb_memtable_t *mt);

/**
 * tidesdb_l0_release_immutable
 * return a claimed immutable to the claimable set without retiring it, for a flush that failed. the
 * claim is what stops two workers taking the same immutable, so a failure that keeps it would leave
 * the immutable in the queue forever -- never re-claimed, never flushed, its data reaching L1 only
 * through a WAL replay on the next open. the next rotation's wake picks it up again
 * @param l0 the subsystem
 * @param mt the claimed immutable to release, may be NULL
 */
void tidesdb_l0_release_immutable(tidesdb_l0_t *l0, tidesdb_memtable_t *mt);

/**
 * tidesdb_l0_queue_depth
 * the current number of immutable memtables awaiting flush; the write path paces on this, not the
 * raw count of flushed-but-pinned memtables
 * @param l0 the subsystem
 * @return the immutable queue depth
 */
size_t tidesdb_l0_queue_depth(const tidesdb_l0_t *l0);

/**
 * tidesdb_l0_active_bytes
 * the memory the active memtable occupies, the figure the rotation threshold is compared against,
 * for db-level stats. a memtable is a memory budget, so this counts the skip list nodes, their
 * pointer arrays and the version structs alongside the key and value bytes
 * @param l0 the subsystem
 * @return the active memtable size in bytes, or 0 if none is pinnable
 */
size_t tidesdb_l0_active_bytes(tidesdb_l0_t *l0);

/**
 * tidesdb_l0_mark_aborted
 * record that a commit sequence was abandoned after its batch was already durable, so the entries
 * it managed to apply are hidden from reads and dropped by the flush that would otherwise carry
 * them to L1
 * @param l0 the subsystem
 * @param seq the abandoned commit sequence
 * @return TDB_SUCCESS, or TDB_ERR_MEMORY_LIMIT when the table is full
 */
int tidesdb_l0_mark_aborted(tidesdb_l0_t *l0, uint64_t seq);

/**
 * tidesdb_l0_seq_aborted
 * whether a sequence was abandoned; the read and flush paths consult this before honouring a
 * version
 * @param l0 the subsystem
 * @param seq the sequence to test
 * @return non-zero when the sequence was abandoned
 */
int tidesdb_l0_seq_aborted(const tidesdb_l0_t *l0, uint64_t seq);

/**
 * tidesdb_l0_admit_write
 * pace one writer against current L0 fill before its write is made durable -- snapshot the
 * pressure, ask the backpressure policy, and dwell or wait out a full queue as it decides. an
 * unbounded queue limit admits immediately, so the whole mechanism is opt-in through configuration.
 * a writer that waits out the ceiling without the queue draining is admitted anyway, so a wedged
 * flush degrades ingestion instead of hanging it. an empty immutable queue also admits without
 * consulting the policy, since this paces against the unflushed backlog and there is none -- a
 * policy pacing on active memtable fill alone is therefore not driven from here
 * @param l0 the subsystem
 * @return TDB_SUCCESS once the writer may proceed, or TDB_ERR_INVALID_ARGS if l0 is NULL
 */
int tidesdb_l0_admit_write(tidesdb_l0_t *l0);

/**
 * tidesdb_l0_set_tier_depth
 * publish the deepest flush tier across the families, so admission can pace ingestion against merge
 * progress rather than against flush progress alone
 * @param l0 the subsystem
 * @param depth runs in the deepest family's flush tier
 */
void tidesdb_l0_set_tier_depth(tidesdb_l0_t *l0, int depth);

/**
 * tidesdb_l0_admission_t
 * what write admission has done since the subsystem was created
 * @param throttled writers the policy made dwell before admitting
 * @param blocked writers the policy made wait for the queue to drain
 * @param stall_us total microseconds writers were held in admission, dwell plus wait
 * @param ceiling_hits writers admitted only because the wait ceiling expired
 * @param max_us the longest single hold, which the total alone cannot distinguish from many
 *              short dwells
 */
typedef struct
{
    uint64_t throttled;
    uint64_t blocked;
    uint64_t stall_us;
    uint64_t ceiling_hits;
    uint64_t max_us;
} tidesdb_l0_admission_t;

/**
 * tidesdb_l0_wal_wait_t
 * how long appends have been made to wait on the write-ahead log
 * @field count appends that waited
 * @field total_us the summed wait
 * @field max_us the longest single wait
 */
typedef struct
{
    uint64_t count;
    uint64_t total_us;
    uint64_t max_us;
} tidesdb_l0_wal_wait_t;

/**
 * tidesdb_l0_wal_wait_stats
 * read the log-append wait totals
 * @param l0 the subsystem, may be NULL
 * @param out out -- the totals, zeroed when l0 is NULL
 */
void tidesdb_l0_wal_wait_stats(const tidesdb_l0_t *l0, tidesdb_l0_wal_wait_t *out);

/**
 * tidesdb_l0_wal_bytes_written
 * framed bytes ever handed to the write-ahead log
 * @param l0 the l0 subsystem
 * @return the byte total, or 0 if l0 is NULL
 */
uint64_t tidesdb_l0_wal_bytes_written(const tidesdb_l0_t *l0);

/**
 * tidesdb_l0_admission_stats
 * read the write-admission counters, so a caller can tell whether pacing engaged and what it cost
 * @param l0 the subsystem
 * @param out out -- the counters, untouched if either argument is NULL
 */
void tidesdb_l0_admission_stats(const tidesdb_l0_t *l0, tidesdb_l0_admission_t *out);

/**
 * tidesdb_memtable_mark_flushed
 * mark an immutable durably written to L1 so reclamation may free it; sets the flushed flag only
 * @param mt the memtable
 */
void tidesdb_memtable_mark_flushed(tidesdb_memtable_t *mt);

/**
 * tidesdb_l0_pin_memtables
 * reference the active memtable and every immutable for a snapshot scan, newest first, so a reader
 * can open a cursor over each; the caller drops them with tidesdb_l0_unpin_memtables. references
 * all or nothing -- when more memtables exist than fit in out, nothing is pinned and the needed
 * count is returned so the caller sizes up and retries
 * @param l0 the subsystem
 * @param out destination array receiving the pinned memtables
 * @param max capacity of out
 * @param n_out out -- the number pinned on success, or the number needed when out was too small
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_MEMORY, or TDB_ERR_TOO_LARGE when out is too
 * small
 */
int tidesdb_l0_pin_memtables(tidesdb_l0_t *l0, tidesdb_memtable_t **out, int max, int *n_out);

/**
 * tidesdb_l0_unpin_memtables
 * drop the references a tidesdb_l0_pin_memtables took, freeing any memtable whose last reference
 * this releases
 * @param mts the pinned memtables
 * @param n the number of memtables
 */
void tidesdb_l0_unpin_memtables(tidesdb_memtable_t **mts, int n);

/**
 * tidesdb_l0_reclaim
 * free a dequeued immutable once every reader has drained. the caller must have removed it from the
 * queue (via tidesdb_l0_dequeue_immutable) so no new reader can reach it. it rechecks briefly and
 * frees the skip_list and struct, and hands an immutable readers still hold to a pending list for
 * tidesdb_l0_reclaim_pending rather than waiting on it. the wait is bounded on purpose: this runs
 * inside a flush install, under locks a create or drop needs, and the reader epoch is db-global, so
 * a database under continuous reads may never present the asking thread a quiet instant. the WAL is
 * not closed here -- the flush path closes and unlinks it once the immutable is durable.
 * @param l0 the subsystem, for the reader epoch to check against
 * @param mt the dequeued immutable to free, may be NULL
 */
void tidesdb_l0_reclaim(tidesdb_l0_t *l0, tidesdb_memtable_t *mt);

/**
 * tidesdb_l0_reclaim_pending
 * free every deferred immutable whose readers have since left, returning the rest to the list. safe
 * to call at any time; a caller that never calls it leaks the deferred immutables until close
 * @param l0 the subsystem, may be NULL
 */
void tidesdb_l0_reclaim_pending(tidesdb_l0_t *l0);

#endif /* __TIDESDB_MEMTABLE_H__ */
