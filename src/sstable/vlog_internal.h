/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __VLOG_INTERNAL_H__
#define __VLOG_INTERNAL_H__
#include "base/lockfree.h"
#include "sstable/vlog.h"

/* private to the vlog module -- the segment table and id index shared between vlog.c, which owns
 * the index and the value paths, and vlog_segment.c, which owns segment files and their lifetime */

/* a slot that has never held a segment; also the value a retired slot is left at, so a scan for
 * live segments tests one field */
#define VLOG_SEG_ABSENT 0

/* the slot holds an open segment file readable by anyone holding a reference */
#define VLOG_SEG_OPEN 1

/* the refcount a live segment rests at when no reader is inside it: the table's own reference */
#define VLOG_SEG_BASELINE 1

/* a path buffer large enough for a store directory plus a segment name */
#define VLOG_PATH_MAX 1024

/* an append retries this many times before giving up, so a thread cannot spin forever if others
 * keep winning the roll. every kind of lost race shares this budget -- arriving at a segment that
 * is being retired, and finding the active one already full -- and under a small segment target a
 * reclaim rolls and retires often enough to cost several in a row. a tight budget turned that
 * ordinary churn into a write failure, so it is generous: far past any real contention, and still a
 * fixed bound rather than an unbounded spin */
#define VLOG_APPEND_MAX_ATTEMPTS 64

/* how long an append pauses when the segment table has no free slot, giving a reclaim in flight a
 * moment to retire one. the table is only ever transiently full while reclamation catches up, so
 * failing the write outright would report a lost race as an error */
#define VLOG_APPEND_FULL_PAUSE_US 200

/* a segment holding no more than this fraction of itself live is worth putting through compaction
 * to empty it, as a divisor: a half. rewriting the tables that reference a mostly-live segment
 * would move nearly all of it forward to recover nearly nothing, so the threshold is what keeps
 * reclamation from costing more than it reclaims.
 *
 * a quarter was too strict to fire. under a random update load every segment decays at about the
 * same rate, so they sit together around half live and none of them individually crosses a quarter
 * -- the store stayed at twice the size of its data with nothing ever marked. at a half a segment
 * pays back at least as much space as the rewrite costs, which is the point where draining is still
 * worth doing */
#define VLOG_RECLAIM_LIVE_DIVISOR 2

/* no segment number is below this, so a store with no builder in flight protects nothing */
#define VLOG_BUILD_FLOOR_NONE UINT64_MAX

/* how many builders can be in flight at once. flush and compaction threads are configured well
 * below this, and a builder that cannot claim a slot is refused rather than left unprotected */
#define VLOG_MAX_BUILDERS 256

/* index bucket occupancy states for the open-addressed id map */
#define VLOG_BUCKET_EMPTY    0
#define VLOG_BUCKET_OCCUPIED 1
#define VLOG_BUCKET_DELETED  2

/* map starts small and doubles past a 3/4 load factor */
#define VLOG_INDEX_INITIAL_CAP 64
#define VLOG_INDEX_LOAD_NUM    3
#define VLOG_INDEX_LOAD_DEN    4

/**
 * vlog_segment_t
 * one append-only segment file and the state deciding when it may be drained and freed
 * @field bm the block manager over the segment file, owned by the store and closed on retire, or
 *        NULL while the reaper has taken its descriptor back. reopened on demand, published by a
 *        compare-exchange, so a reader that finds it absent is delayed rather than failed
 * @field number the ascending file number, which is also what recovery orders segments by
 * @field rc references held by readers currently inside the segment, above the table's own; a
 *        retire waits for it to fall back to VLOG_SEG_BASELINE
 * @field state VLOG_SEG_OPEN while the file is usable, VLOG_SEG_ABSENT before first use and after
 *        the file is unlinked
 * @field live_bytes framed bytes the live sstables referencing this segment still hold in it,
 * summed from their footers. the store cannot derive this itself -- which values are still
 * reachable is known only to the trees -- so they report it as they are installed and dropped, and
 * a segment falling to zero is one nothing can reach any more
 * @field live_count how many values those bytes are, kept beside them because a segment holding a
 *        few large values and one holding many small ones want different reclamation decisions
 * @field draining set when the segment holds little enough live data to be worth emptying, which
 *        makes the next compaction carrying one of its values rewrite the value instead
 */
typedef struct
{
    _Atomic(block_manager_t *) bm;
    uint64_t number;
    tdb_refcount_t rc;
    _Atomic(int) state;
    _Atomic(uint64_t) live_bytes;
    _Atomic(uint64_t) live_count;
    _Atomic(int) draining;
} vlog_segment_t;

/**
 * vlog_index_entry_t
 * one live value's location, as a segment slot and an offset within that segment's file
 * @field id the logical value id, non-zero when the bucket is occupied
 * @field offset block offset within the segment
 * @field value_len uncompressed value length
 * @field disk_len framed bytes the value's block occupies in its segment, which is what per-segment
 *        space accounting has to be stated in -- a logical length would not say how much of a file
 *        a table actually holds once framing and compression are counted
 * @field chain the encoding chain the value was written through, packed one codec id per byte.
 *        carried per value rather than taken from the store or the family, because a family can
 *        change its codec and compaction rewrites values under whichever pipeline is merging them,
 *        so the only thing that knows what encoded a value is the value
 * @field segment slot index into the store's segment table
 * @field state bucket occupancy, one of the VLOG_BUCKET_* values
 */
typedef struct
{
    uint64_t id;
    uint64_t offset;
    uint64_t value_len;
    uint64_t disk_len;
    uint64_t chain;
    uint32_t segment;
    uint8_t state;
} vlog_index_entry_t;

/**
 * vlog
 * the value store: a fixed table of segment files, one of them taking appends, over an id index
 * mapping every live value to the segment and offset holding it
 * @field dir the store directory, copied at open so segment paths can be rebuilt without the caller
 * @field fdm borrowed descriptor budget segment files are opened against, or NULL
 * @field sync_mode block manager sync mode every segment is opened with
 * @field encodings the db-global encoding registry a value's recorded chain resolves against,
 *        borrowed. db-global rather than per-family because compaction moves a value forward by id
 *        and the family merging it may by then run a different pipeline
 * @field segment_target_bytes size at which the active segment seals and a fresh one opens
 * @field next_id the id the next write assigns
 * @field next_number the file number the next segment created will carry
 * @field active_slot table index of the segment currently taking appends
 * @field seg_high one past the highest slot ever used, so a scan stops early rather than walking
 *        the whole table
 * @field roll_mu serializes sealing the active segment and opening its successor, so exactly one
 *        thread creates each segment file
 * @field segments the fixed segment table; a slot's address never moves, which is what lets a
 *        reader hold one across an unlocked read
 * @field index_rw guards the id map, the space counters and every index repoint. a reader-writer
 *        lock rather than a mutex because resolving an id is a read and nothing else: every value a
 *        scan dereferences goes through here, so a mutex made the store's own index the thing
 *        concurrent readers waited on rather than the device
 * @field buckets the open-addressed id map
 * @field bucket_cap capacity of buckets, a power of two
 * @field bucket_count occupied buckets
 * @field bucket_tomb deleted buckets awaiting a resize
 * @field used_bytes uncompressed length the indexed values represent
 * @field stored_bytes framed length those same values occupy on disk. read against used_bytes it is
 *        what the encoding pipeline actually bought, measured on the values the store still holds
 *        rather than on a sample
 * @field chain_keys the packed chains seen, chain_n of them
 * @field chain_used uncompressed bytes attributed to each chain
 * @field chain_stored on-disk bytes attributed to each chain
 * @field chain_values how many values each chain accounts for
 * @field chain_n how many chains are in use
 * @field reclaim_calls reclaim calls made, lifetime, whether or not any segment was worth
 *        draining. read beside reclaim_passes it separates a reclaim that never runs from one that
 *        runs and finds nothing, which are different faults with different fixes
 * @field reclaim_passes reclaim calls that drained at least one segment, lifetime; a call
 *        drains every segment worth draining, so this counts calls and segments_retired
 *        counts what they freed
 * @field segments_retired segment files unlinked by a reclaim, lifetime
 * @field build_floors one slot per builder in flight, holding the lowest segment number that
 * builder may have written a value into, or VLOG_BUILD_FLOOR_NONE when the slot is free. a segment
 * at or above the lowest floor held cannot be reclaimed, since a builder may have put a value in it
 * that no installed sstable references yet
 * @field builds_unslotted builders that found no free slot in build_floors and so cannot be
 *        described individually. any of them stops reclamation entirely, there being no way to say
 *        which segments they might have reached
 */
struct vlog
{
    char dir[VLOG_PATH_MAX];
    fd_manager_t *fdm;
    int sync_mode;
    const tidesdb_encoding_registry_t *encodings;
    uint64_t segment_target_bytes;
    _Atomic(uint64_t) next_id;
    _Atomic(uint64_t) next_number;
    _Atomic(uint32_t) active_slot;
    _Atomic(uint32_t) seg_high;
    pthread_mutex_t roll_mu;
    vlog_segment_t segments[VLOG_MAX_SEGMENTS];

    pthread_rwlock_t index_rw;
    vlog_index_entry_t *buckets;
    size_t bucket_cap;
    size_t bucket_count;
    size_t bucket_tomb;
    uint64_t used_bytes;
    uint64_t stored_bytes;
    uint64_t chain_keys[VLOG_MAX_CHAINS];
    uint64_t chain_used[VLOG_MAX_CHAINS];
    uint64_t chain_stored[VLOG_MAX_CHAINS];
    uint64_t chain_values[VLOG_MAX_CHAINS];
    int chain_n;

    /* every byte this log has ever appended, reclamation's own rewrites included. the live and
     * stored totals describe what is held now, which cannot answer what the device was asked to
     * write -- and for a store that separates its values, that is most of the writing there is */
    _Atomic(uint64_t) bytes_written;
    _Atomic(uint64_t) reclaim_calls;
    _Atomic(uint64_t) reclaim_passes;
    _Atomic(uint64_t) segments_retired;
    _Atomic(uint64_t) build_floors[VLOG_MAX_BUILDERS];
    _Atomic(int) builds_unslotted;
};

/**
 * vlog_segment_name
 * formats a segment file name from its number
 * @param number the segment number
 * @param out receives the name
 * @param out_size capacity of out
 * @return VLOG_OK or VLOG_ERR_INVALID when the name would not fit
 */
int vlog_segment_name(uint64_t number, char *out, size_t out_size);

/**
 * vlog_segment_scan_dir
 * collects the numbers of every segment file in dir, ascending, so recovery adopts them in write
 * order. a directory that cannot be opened is an empty store rather than an error, which is what
 * makes a first open work
 * @param dir the store directory
 * @param numbers receives the numbers found
 * @param max capacity of numbers
 * @param out_count receives how many were found
 * @return VLOG_OK or VLOG_ERR_FULL when dir holds more segments than max
 */
int vlog_segment_scan_dir(const char *dir, uint64_t *numbers, size_t max, size_t *out_count);

/**
 * vlog_segment_open
 * opens the segment file with this number into the next free table slot
 * @param v the store
 * @param number the segment number to open
 * @param out_slot receives the table slot the segment occupies
 * @return VLOG_OK, VLOG_ERR_IO if the file could not be opened, or VLOG_ERR_FULL when the table has
 *         no free slot
 */
int vlog_segment_open(vlog_t *v, uint64_t number, uint32_t *out_slot);

/**
 * vlog_segment_ensure_open
 * the segment's block manager, reopening the file when the reaper has taken its descriptor. the
 * caller must already hold a reference from vlog_segment_acquire, which is what keeps an eviction
 * from racing the handle it is about to use
 * @param v the store
 * @param slot table slot
 * @return the block manager, or NULL when the file could not be reopened
 */
block_manager_t *vlog_segment_ensure_open(vlog_t *v, uint32_t slot);

/**
 * vlog_segment_evict
 * closes an idle segment's file, giving its descriptor back while leaving the segment usable. a
 * segment with a reader inside it is left alone
 * @param v the store
 * @param slot table slot
 * @return 1 when a descriptor was released, 0 otherwise
 */
int vlog_segment_evict(vlog_t *v, uint32_t slot);

/**
 * vlog_segment_acquire
 * takes a reference so the segment's file cannot be closed and unlinked while it is read
 * @param v the store
 * @param slot table slot to reference
 * @return 1 if a reference was taken, 0 if the slot holds no live segment
 */
int vlog_segment_acquire(vlog_t *v, uint32_t slot);

/**
 * vlog_segment_release
 * drops a reference taken by vlog_segment_acquire
 * @param v the store
 * @param slot table slot to release
 */
void vlog_segment_release(vlog_t *v, uint32_t slot);

/**
 * vlog_segment_retire
 * closes and unlinks a drained segment once no reader is inside it, freeing its slot. the caller
 * must already have repointed every live value that was in it
 * @param v the store
 * @param slot table slot to retire
 * @return VLOG_OK, VLOG_ERR_IO when readers did not drain in time and the segment was left open for
 *         a later attempt, or VLOG_ERR_BUSY when a roll made this the active segment after the
 *         caller chose it, in which case it is left open and taking appends
 */
int vlog_segment_retire(vlog_t *v, uint32_t slot);

/**
 * vlog_segment_roll
 * seals the active segment and opens its successor, when the caller has observed the active one at
 * or past its target size. a second caller that lost the race observes the new active segment and
 * does nothing
 * @param v the store
 * @param full_slot the slot the caller observed as full
 * @return VLOG_OK, VLOG_ERR_IO, or VLOG_ERR_FULL
 */
int vlog_segment_roll(vlog_t *v, uint32_t full_slot);

/**
 * vlog_segment_append
 * appends one already-framed payload to the active segment, rolling first if it is full
 * @param v the store
 * @param payload the block payload, its vlog header included
 * @param payload_len length of payload
 * @param out_slot receives the slot the payload landed in
 * @param out_offset receives the block offset within that segment
 * @return VLOG_OK, VLOG_ERR_IO, or VLOG_ERR_FULL
 */
int vlog_segment_append(vlog_t *v, const uint8_t *payload, size_t payload_len, uint32_t *out_slot,
                        uint64_t *out_offset);

/**
 * vlog_index_locate
 * finds the bucket holding id, or the bucket where it would be inserted
 * @param v vlog handle
 * @param id id to locate, must be non-zero
 * @param out_free receives the first reusable (empty or deleted) bucket seen, may be NULL
 * @return index of the occupied bucket holding id, or SIZE_MAX if absent
 */
size_t vlog_index_locate(const vlog_t *v, uint64_t id, size_t *out_free);

/**
 * vlog_chain_account
 * moves a value's bytes into or out of its chain's totals
 * @param v vlog handle, index_rw held for writing
 * @param key the packed chain
 * @param used uncompressed bytes, negated to remove
 * @param stored on-disk bytes, negated to remove
 * @param values value count delta
 */
void vlog_chain_account(vlog_t *v, uint64_t key, int64_t used, int64_t stored, int64_t values);

#endif /* __VLOG_INTERNAL_H__ */
