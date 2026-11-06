/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __VLOG_H__
#define __VLOG_H__
#include "base/encoding/compress.h"
#include "base/encoding/encoding.h"
#include "compat.h"
#include "fdmanager/fdmanager.h" /* the shared descriptor budget segment files are held to */
#include "io/block_manager.h"

/* the value log stores separated values (those at or above the owning column family's klog value
 * threshold) in one db-global store shared by every family. a klog entry references a value by an
 * opaque logical id, never a physical offset, so reclamation can relocate a value's bytes without
 * rewriting any sstable. each value is one block manager block whose payload is a small header (the
 * id, the uncompressed length, and the chain of encodings the value was written through) followed
 * by the stored bytes, so a read is a single block fetch and the store packs tightly regardless of
 * value size. the chain travels with the value because compaction carries a value forward by id
 * without re-encoding it, so the sstable referencing it may record a different pipeline by then.
 *
 * the store is a series of append-only segment files rather than one file. exactly one segment is
 * open for appends; it seals at a target size and a fresh one takes over, and a sealed segment is
 * immutable for the rest of its life. that is what makes reclamation concurrent: a value is
 * reclaimed by copying it into the active segment through the ordinary append path and repointing
 * its index entry, never by moving bytes underneath a reader, so no reader, writer, flush or
 * compaction is ever excluded for the duration.
 *
 * the vlog holds no notion of which values are still referenced -- that truth lives with the
 * klogs. rather than read them to find out, every sstable records at build time which segments its
 * separated values landed in and how many bytes of each they hold, and the store is told those
 * totals as tables come and go. a segment whose total falls to zero is reachable from nothing and
 * is dropped outright, with no scan and nothing copied.
 *
 * that leaves segments that are mostly but not entirely dead, and they are emptied by compaction
 * rather than by the store: the tables still referencing such a segment are rewritten, re-spilling
 * those values into current segments, after which the old segment reaches zero and is dropped the
 * cheap way. reclamation therefore costs a compaction that was going to happen anyway, and the
 * store never moves bytes underneath a reader. */

/* an id of 0 means the entry carries no separated value; the first value written gets id 1. */
#define VLOG_ID_INVALID 0

/* value-block payload header, carved from the front of every block's payload. the id lets recovery
 * and reclamation identify a block; the length lets a read size the decompressed value. */
#define VLOG_BLK_ID_SIZE  8
#define VLOG_BLK_LEN_SIZE 8
#define VLOG_BLK_HDR_SIZE (VLOG_BLK_ID_SIZE + VLOG_BLK_LEN_SIZE)

/* the length word carries the number of encodings the value was written through in its top byte,
 * and that many encoding ids follow the fixed header, in the order they were applied. a value's
 * length is bounded by the uint32 block frame, so the upper half of the word was never used.
 *
 * every value describes its own encoding, and that is not a convenience -- compaction carries a
 * spilled value forward by id without re-reading or re-encoding it, so a value written under one
 * pipeline can end up referenced by an sstable whose footer records a different one. a value that
 * described itself by anything other than its own bytes would then be decoded with the wrong chain.
 * it is also what lets one shared store hold values from families that encode differently */
#define VLOG_BLK_CHAIN_SHIFT 56
#define VLOG_BLK_LEN_MASK    ((1ULL << VLOG_BLK_CHAIN_SHIFT) - 1)

/* segment files are named by a zero-padded ascending number followed by an extension, the same
 * shape a key log and a write ahead log use, so a directory listing sorts into write order and
 * reads consistently whatever kind of file is being looked at */
#define VLOG_SEGMENT_EXT      ".vlog"
#define VLOG_SEGMENT_DIGITS   12
#define VLOG_SEGMENT_NAME_MAX 32

/* the segment table is sized once at open and never grows, so a segment's slot address is stable
 * for the life of the store and a reader can hold one without a lock */
#define VLOG_DEFAULT_MAX_SEGMENTS 4096
#define VLOG_MAX_SEGMENTS         65536

/* legacy and ordinary values have no shard-group owner. this is deliberately outside every
 * caller-supplied group range, including a range whose ceiling is UINT32_MAX. */
#define VLOG_GROUP_UNGROUPED UINT32_MAX

/* an append rolls to a fresh segment once the active one reaches this, unless the config overrides
 * it. large enough that rolling is rare and descriptor pressure stays low, small enough that
 * draining one segment is a bounded amount of copying */
#define VLOG_DEFAULT_SEGMENT_TARGET_BYTES (256ull * 1024 * 1024)

/* one background tick may request no more than this much sealed value-log data or this many
 * positioned reads. callers pass these limits to vlog_scrub_pass so its scheduling contract is
 * visible without exposing its private cursor state. */
#define VLOG_SCRUB_PASS_BYTES (256u * 1024u)
#define VLOG_SCRUB_PASS_READS 32u

/* return codes. 0 is success, negatives are distinct failures so callers can react (a corrupt
 * read is recoverable by retry from another sstable, a missing id is a logic error). */
#define VLOG_OK             0
#define VLOG_ERR_INVALID    (-1)
#define VLOG_ERR_IO         (-2)
#define VLOG_ERR_CORRUPTION (-3)
#define VLOG_ERR_MEMORY     (-4)
#define VLOG_ERR_NOT_FOUND  (-5)
#define VLOG_ERR_FULL       (-6)
#define VLOG_ERR_BUSY       (-7)
#define VLOG_ERR_RANGE      (-8)

/* opaque logical value id stored in a klog entry in place of a physical offset. */
typedef uint64_t vlog_id_t;

/* opaque handle. the segment table, id index and recovery state are private to the module. */
typedef struct vlog vlog_t;

/**
 * vlog_config_t
 * what a vlog is opened with, sourced from the owning database config
 * @param sync_mode block manager sync mode every segment file is opened with
 * @param segment_target_bytes size at which the active segment seals and a fresh one opens
 * @param max_segments simultaneous segment slots including the active one, 0 for the default
 * @param enable_vlog_indexes whether segments publish a rebuildable index at checkpoints and seal
 * @param blob_scrub_enabled whether sealed segments retain their exact logical extent for bounded
 *        read-only background verification
 * @param encodings the db-global registry a stored value's recorded ids resolve against. the
 *        registry is db-global even though a pipeline is per-family, so the store can decode any
 *        value it holds
 * @param fdm the descriptor budget segment files open against, borrowed, or NULL to open them
 *        directly. a store can hold thousands of segments, so leaving them outside the budget that
 *        klogs and write ahead logs respect would let the value log exhaust the process on its own
 */
typedef struct
{
    int sync_mode;
    uint64_t segment_target_bytes;
    int enable_vlog_indexes;
    int blob_scrub_enabled;
    uint32_t max_segments;
    uint32_t max_blob_shard_groups;
    const tidesdb_encoding_registry_t *encodings;
    fd_manager_t *fdm;
} vlog_config_t;

/**
 * vlog_stats_t
 * a point-in-time physical accounting. the vlog cannot report reclaimable space on its own because
 * it does not know which values are dead; the engine tracks that with its own dropped-bytes hint
 * and decides when to trigger a reclaim
 * @param file_size total bytes across every segment
 * @param value_count values currently indexed
 * @param used_bytes uncompressed length the indexed values represent
 * @param stored_bytes framed length those same values occupy on disk, so used over stored is what
 *        the encoding pipeline is actually buying on the data the store holds
 * @param segment_count segments currently open, the active one included
 * @param dead_bytes bytes held by segments beyond what their live values account for,
 *        derived from the index rather than tracked, so it needs no caller to report a drop
 * @param live_bytes framed bytes the store's live sstables still reference, summed from what they
 *        reported. this is the figure space amplification is against: used_bytes counts everything
 *        the index still names, which includes values no tree can reach any more, so it converges
 *        on the file size and says nothing about how much of the store is worth keeping
 * @param bytes_written every byte ever appended, reclamation's rewrites included. this is the
 *        write-amplification term for a separated value; the live and stored totals say what is
 *        held, not what the device was asked to write
 * @param reclaim_calls reclaim calls made, lifetime, whether or not anything was drained
 * @param reclaim_passes reclaim calls that drained at least one segment, lifetime; one call
 *        drains every segment worth draining, so segments_retired may exceed this
 * @param segments_retired segment files unlinked by a reclaim, lifetime
 * @param segments_drainable sealed segments holding so little live data that rewriting the tables
 *        referencing them would free most of a file, as of the last reclaim. dead_bytes says how
 *        much there is to reclaim and this says how much of it is currently actionable
 */
typedef struct
{
    uint64_t file_size;
    uint64_t value_count;
    uint64_t used_bytes;
    uint64_t stored_bytes;
    uint64_t segment_count;
    uint64_t dead_bytes;
    uint64_t live_bytes;
    uint64_t bytes_written;
    uint64_t reclaim_calls;
    uint64_t reclaim_passes;
    uint64_t segments_retired;
    uint64_t segments_drainable;
} vlog_stats_t;

/**
 * vlog_scrub_pass_t
 * outcome of one bounded sealed-value-log verification slice
 * @param bytes_read bytes requested from storage in this slice
 * @param frame_offset frame header offset checked or resumed
 * @param segment_number physical segment carrying the frame
 * @param reads positioned reads attempted in this slice
 * @param group VLOG_GROUP_UNGROUPED for ordinary values, otherwise the shard owner
 * @param complete nonzero when the selected segment reached its sealed logical end
 */
typedef struct
{
    size_t bytes_read;
    uint64_t frame_offset;
    uint64_t segment_number;
    size_t reads;
    uint32_t group;
    int complete;
} vlog_scrub_pass_t;

/* how many distinct encoding chains the store accounts for separately, and so the most
 * vlog_get_chain_stats can report. a family changes its codec rarely, and every change leaves
 * values behind under the old chain, so a handful of buckets covers a store's whole history. values
 * beyond this share the last bucket rather than being miscounted against a chain that did not write
 * them */
#define VLOG_MAX_CHAINS 16

/**
 * vlog_chain_stats_t
 * what one encoding chain achieved on the values it wrote, which is the only honest way to report a
 * codec's effect: a family can change its codec, and compaction rewrites values under whichever
 * pipeline is merging them, so a single figure for the store would average across chains and
 * describe none of them
 * @param ids the codec ids in the order applied, empty when the values were stored verbatim
 * @param id_count how many ids
 * @param used_bytes uncompressed length of the values written through this chain
 * @param stored_bytes the on-disk length those values occupy, so used over stored is the ratio
 * @param value_count how many values it accounts for
 */
typedef struct
{
    uint8_t ids[TDB_ENCODING_PIPELINE_MAX];
    int id_count;
    uint64_t used_bytes;
    uint64_t stored_bytes;
    uint64_t value_count;
} vlog_chain_stats_t;

/**
 * vlog_segment_info_t
 * one segment's identity and logical length, for a caller copying the store elsewhere
 * @param number segment file number, formatted into a name only by the file-owning consumer
 * @param group VLOG_GROUP_UNGROUPED for a root file; otherwise its authoritative shard owner
 * @param logical_size bytes to copy for a faithful duplicate; a preallocated tail beyond this is
 *        not part of the segment's contents
 */
typedef struct
{
    uint64_t number;
    uint32_t group;
    uint64_t logical_size;
} vlog_segment_info_t;

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
 * vlog_open
 * opens the value log rooted at dir, adopting every segment already present and rebuilding the id
 * index from their blocks, then opening an active segment for appends. an absent or empty set of
 * segments is a fresh store, not an error
 * @param dir directory holding the segment files, borrowed for the call only
 * @param config codec, durability and segment sizing
 * @param out receives the handle on success
 * @return VLOG_OK, VLOG_ERR_INVALID on bad args, VLOG_ERR_MEMORY, VLOG_ERR_IO, or VLOG_ERR_FULL
 *         when the retained nonempty files leave no slot for the fresh active segment
 */
int vlog_open(const char *dir, const vlog_config_t *config, vlog_t **out);

/* engine open holds the directory lock and has already validated all grouped headers before
 * opening its manifest. avoid repeating that disk pass during value-log adoption. */
int vlog_open_after_preflight(const char *dir, const vlog_config_t *config, vlog_t **out);

/**
 * vlog_max_segments
 * the fixed capacity selected when the store was opened
 * @param vlog open store, or NULL for the default
 * @return the maximum simultaneous segment count, including the active segment
 */
uint32_t vlog_max_segments(const vlog_t *vlog);

/**
 * vlog_close
 * closes every segment the store owns and releases the index; segment files are left on disk
 * @param vlog handle to close (may be NULL)
 */
void vlog_close(vlog_t *vlog);

/**
 * vlog_scrub_pass
 * verify a bounded piece of one sealed segment, round-robin selecting another segment when the
 * prior target completed or was retired; no segment reference or descriptor is held after return
 * @param vlog open store, with a single caller driving the cursor; a disabled store does no work
 * @param byte_budget maximum bytes requested in this call, at least one frame header
 * @param read_budget maximum positioned reads attempted in this call
 * @param out receives work and the segment/frame identity
 * @return VLOG_OK, VLOG_ERR_CORRUPTION, VLOG_ERR_IO, VLOG_ERR_MEMORY, or VLOG_ERR_INVALID
 */
int vlog_scrub_pass(vlog_t *vlog, size_t byte_budget, size_t read_budget, vlog_scrub_pass_t *out);

/**
 * vlog_write
 * compresses a value, appends it as one block to the active segment, and returns its logical id.
 * rolls to a fresh segment first when the active one has reached its target size
 * @param vlog handle
 * @param value value bytes, borrowed until this call returns; may be NULL only when value_len is
 *              zero
 * @param value_len length of value, including zero for a separated empty value
 * @param ids the encoding ids to apply, in order, recorded with the value so a later read undoes
 *        exactly what was applied whatever any family or sstable is configured with by then
 * @param id_count how many ids, 0 to store the value verbatim
 * @param out_id receives the id to store in the klog entry
 * @param out_disk_bytes optional, receives the framed on-disk bytes the block occupies so a caller
 *        can attribute its own contribution to the shared store (may be NULL)
 * @return VLOG_OK, VLOG_ERR_INVALID, VLOG_ERR_MEMORY, VLOG_ERR_IO, or VLOG_ERR_FULL when no
 *         further segment can be opened
 */
int vlog_write(vlog_t *vlog, const uint8_t *value, size_t value_len, const uint8_t *ids,
               int id_count, vlog_id_t *out_id, uint64_t *out_disk_bytes);

/**
 * vlog_write_group
 * appends a verbatim blob to its explicitly selected shard-group segment
 * @param vlog open store with grouped blobs enabled
 * @param group shard-group id, below vlog_group_limit and never VLOG_GROUP_UNGROUPED
 * @param value bytes borrowed until this call returns, NULL only for an empty blob
 * @param value_len byte length of value
 * @param out_id receives the logical value id
 * @param out_disk_bytes optional framed byte count
 * @return VLOG_OK, VLOG_ERR_INVALID when grouping is disabled or group is out of range,
 *         VLOG_ERR_MEMORY, VLOG_ERR_IO, or VLOG_ERR_FULL
 */
int vlog_write_group(vlog_t *vlog, uint32_t group, const uint8_t *value, size_t value_len,
                     vlog_id_t *out_id, uint64_t *out_disk_bytes);

/**
 * vlog_group_limit
 * returns the configured exclusive shard-group upper bound, or zero when grouping is disabled
 * @param vlog open store, or NULL
 * @return group ceiling
 */
uint32_t vlog_group_limit(const vlog_t *vlog);

/**
 * vlog_group_owner_of
 * resolves a value's persisted shard-group owner, returning the ungrouped sentinel for ordinary
 * and legacy values
 * @param vlog open store
 * @param id indexed logical value id
 * @param out_group receives a group id or VLOG_GROUP_UNGROUPED
 * @return VLOG_OK, VLOG_ERR_INVALID, or VLOG_ERR_NOT_FOUND
 */
int vlog_group_owner_of(vlog_t *vlog, vlog_id_t id, uint32_t *out_group);

/**
 * vlog_seal_idle_groups
 * seals up to max currently active grouped segments without allocating successors, or all when max
 * is zero; their next write lazily opens a fresh segment
 * @param vlog open store
 * @param max maximum grouped segments to seal, or zero for all
 * @param out_freed optional count of resident handles actually released
 * @return number sealed, or VLOG_ERR_INVALID for a NULL store
 */
int vlog_seal_idle_groups(vlog_t *vlog, int max, int *out_freed);

/**
 * vlog_read
 * reads a value's block, verifies it, and returns the decompressed bytes. takes no lock a
 * reclamation holds, so a concurrent reclaim never delays a read
 * @param vlog handle
 * @param id logical id from the klog entry, must not be VLOG_ID_INVALID
 * @param out_value receives a newly allocated buffer the caller frees
 * @param out_len receives the value length
 * @return VLOG_OK, VLOG_ERR_NOT_FOUND if the id is unknown, VLOG_ERR_CORRUPTION on a bad block,
 *         VLOG_ERR_MEMORY, or VLOG_ERR_IO
 */
int vlog_read(vlog_t *vlog, vlog_id_t id, uint8_t **out_value, size_t *out_len);

/**
 * vlog_read_range
 * reads a bounded value slice after validating the resolved record's complete block checksum
 * @param vlog value log handle
 * @param id non-zero logical value id
 * @param offset byte offset within the uncompressed value
 * @param length bytes to return, including zero at EOF
 * @param out_value receives an allocated slice the caller frees, or NULL for an empty slice
 * @param out_len receives length on success, zero for an empty slice
 * @return VLOG_OK, VLOG_ERR_INVALID, VLOG_ERR_NOT_FOUND, VLOG_ERR_RANGE when offset and length
 *         are outside the value, VLOG_ERR_CORRUPTION for a bad frame or value metadata,
 *         VLOG_ERR_MEMORY, or VLOG_ERR_IO for a positioned storage failure
 */
int vlog_read_range(vlog_t *vlog, vlog_id_t id, size_t offset, size_t length, uint8_t **out_value,
                    size_t *out_len);

/**
 * vlog_reclaim
 * drops every sealed segment nothing references any more. a segment is reclaimable when the live
 * sstables report holding nothing in it and no builder is in flight that could have written to it,
 * in which case its file is unlinked and its index entries dropped -- no scan, no copying, and no
 * reader excluded, because nothing can resolve into a segment nothing references.
 *
 * a segment that is mostly dead but not empty is not touched here. emptying it means rewriting the
 * tables that still reference it, which is compaction's work, and vlog_mark_drainable names the
 * segments worth doing that for
 * @param vlog handle
 * @return VLOG_OK including when nothing was reclaimable, VLOG_ERR_INVALID, or VLOG_ERR_IO
 */
int vlog_reclaim(vlog_t *vlog);

/**
 * vlog_mark_drainable
 * marks the sealed segments holding so little live data that emptying them would free most of a
 * file. a marked segment's values are re-spilled by the next compaction that carries them rather
 * than copied by the store, so the segment reaches zero through work that was going to happen
 * anyway and is then dropped the cheap way
 * @param vlog handle
 * @return how many segments are marked, or 0 if vlog is NULL
 */
int vlog_mark_drainable(vlog_t *vlog);

/**
 * vlog_group_census_floor
 * capture the oldest possibly uninstalled value before sampling grouped-store table liveness
 * @param vlog open store with groups enabled
 * @return exclusive upper bound for collection using these snapshots
 */
uint64_t vlog_group_census_floor(vlog_t *vlog);

/**
 * vlog_reclaim_before
 * reclaim sealed segments using a previously bounded liveness census
 * @param vlog open store
 * @param census_floor exclusive upper bound, UINT64_MAX for the ordinary ungrouped census
 * @return VLOG_OK or VLOG_ERR_INVALID on an invalid handle
 */
int vlog_reclaim_before(vlog_t *vlog, uint64_t census_floor);

/**
 * vlog_should_respill
 * whether a value sits in a segment being emptied, so a compaction carrying it forward should write
 * it afresh instead of keeping the reference. carrying it would leave the old segment referenced by
 * the new table and no compaction could ever empty it
 * @param vlog handle
 * @param id logical value id
 * @return 1 when the value should be rewritten, 0 otherwise
 */
int vlog_should_respill(vlog_t *vlog, vlog_id_t id);

/**
 * vlog_evict_idle_segments
 * gives back the descriptors of sealed segments nothing is reading, leaving the segments usable --
 * the next read of one reopens its file. a store can hold thousands of segments, so without this
 * the reaper could only relieve descriptor pressure by evicting key logs, however idle the value
 * log's own files were
 * @param vlog handle
 * @param max the most descriptors to release, or 0 for no bound
 * @return how many were released
 */
int vlog_evict_idle_segments(vlog_t *vlog, int max);

/**
 * vlog_build_enter
 * marks a builder as writing values, so no segment it may have landed a value in is judged empty
 * before its table is installed and reports what it holds. a builder that writes a value into a
 * segment which then seals would otherwise leave that segment referenced by nothing installed
 * @param vlog handle
 * @return a token to hand back to vlog_build_leave
 */
int vlog_build_enter(vlog_t *vlog);

/* a token no builder holds, so a caller can tell a slot it never took from one it did */
#define VLOG_BUILD_TOKEN_NONE (-2)

/**
 * vlog_build_protect
 * extend a held floor to a value written before this memtable or prepare took ownership
 * @param vlog handle
 * @param token the token returned by vlog_build_enter
 * @param id logical value id handed to the holder
 */
void vlog_build_protect(vlog_t *vlog, int token, vlog_id_t id);

/**
 * vlog_build_leave
 * marks a builder as finished, releasing what it was protecting
 * @param vlog handle
 * @param token the value vlog_build_enter returned
 */
void vlog_build_leave(vlog_t *vlog, int token);

/**
 * vlog_sync
 * forces every open segment to the device, for a caller establishing a durability barrier across
 * the whole store
 * @param vlog handle
 * @return VLOG_OK, VLOG_ERR_INVALID, or VLOG_ERR_IO if any segment failed to sync
 */
int vlog_sync(vlog_t *vlog);

/**
 * vlog_list_segments
 * snapshots the current segment names and logical lengths, for a caller copying the store. a
 * segment sealed at the time of the call never changes afterwards; the active one may grow past
 * the length reported, which is why the length is part of the snapshot
 * @param vlog handle
 * @param out receives the entries, caller-allocated
 * @param max capacity of out in entries
 * @param out_count receives how many entries were written
 * @return VLOG_OK, VLOG_ERR_INVALID, VLOG_ERR_BUSY when a live segment cannot be pinned,
 *         VLOG_ERR_IO on a size failure or VLOG_ERR_FULL when max is smaller than the segment count
 */
int vlog_list_segments(vlog_t *vlog, vlog_segment_info_t *out, size_t max, size_t *out_count);

/**
 * vlog_backup_inventory
 * captures authoritative lengths while the caller's backup cut excludes appenders, sealing only a
 * nonempty indexed ordinary route and active grouped routes before returning one copy inventory
 * @param vlog open store
 * @param out receives the entries, caller-allocated
 * @param max capacity of out in entries
 * @param out_count receives how many entries were written
 * @return VLOG_OK, VLOG_ERR_INVALID, VLOG_ERR_FULL, or VLOG_ERR_IO
 */
int vlog_backup_inventory(vlog_t *vlog, vlog_segment_info_t *out, size_t max, size_t *out_count);

/**
 * vlog_backup_index
 * strictly validates a source sealed index, then validates its entries against the copied segment
 * and atomically publishes a destination-bound optional index; missing or invalid source indexes
 * are left for ordinary recovery to rebuild
 * @param vlog source store that produced info
 * @param info immutable inventory entry already copied into destination_dir
 * @param source_path captured segment in the protected source store
 * @param copy_path copied segment in the staging directory
 * @param destination_dir backup root containing the copied segment
 * @return VLOG_OK when an index was published or safely omitted, VLOG_ERR_CORRUPTION,
 *         VLOG_ERR_INVALID, VLOG_ERR_MEMORY, or VLOG_ERR_IO for a destination failure
 */
int vlog_backup_index(vlog_t *vlog, const vlog_segment_info_t *info, const char *source_path,
                      const char *copy_path, const char *destination_dir);

/**
 * vlog_get_chain_stats
 * what each encoding chain in the store achieved, one entry per chain seen
 * @param vlog handle
 * @param out receives the entries, caller-allocated
 * @param max capacity of out
 * @param out_count receives how many were written
 * @return VLOG_OK or VLOG_ERR_INVALID
 */
int vlog_get_chain_stats(vlog_t *vlog, vlog_chain_stats_t *out, size_t max, size_t *out_count);

/**
 * vlog_get_stats
 * reads the current space accounting
 * @param vlog handle
 * @param out receives the stats
 * @return VLOG_OK or VLOG_ERR_INVALID
 */
int vlog_get_stats(vlog_t *vlog, vlog_stats_t *out);

/**
 * vlog_next_id
 * the id the next write will assign; captured before a mark scan as the reclaim watermark so a
 * value written after the scan (its id at or above this) is never mistaken for dead
 * @param vlog handle
 * @return the next id, or 0 if vlog is NULL
 */
uint64_t vlog_next_id(vlog_t *vlog);

/**
 * vlog_live_add
 * adds an sstable's hold on a segment, called for each installed table after a vlog_live_reset. the
 * store has no way to learn this on its own, so a table that fails to report is a segment that
 * looks emptier than it is
 * @param vlog handle
 * @param segment the segment number
 * @param bytes framed bytes the table holds there
 * @param count how many values those bytes are
 */
void vlog_live_add(vlog_t *vlog, uint64_t segment, uint64_t bytes, uint64_t count);

/**
 * vlog_live_reset
 * forgets every reported hold, so the caller can restate liveness from the tables installed right
 * now. liveness is restated rather than adjusted as tables come and go because the two error
 * directions are not equal: an unreported drop only delays reclaiming a segment, while a missed
 * install makes a segment holding live values look empty, and that loses them
 * @param vlog handle
 */
void vlog_live_reset(vlog_t *vlog);

/**
 * vlog_segment_of
 * the number of the segment holding a value, which is what an sstable records so the store can
 * later tell how much of a segment its live tables still hold without reading any of them
 * @param vlog handle
 * @param id logical value id
 * @param out_number receives the segment number
 * @param out_disk_bytes optional, receives the framed bytes the value occupies there (may be NULL)
 * @return VLOG_OK, VLOG_ERR_INVALID, or VLOG_ERR_NOT_FOUND if the id is unknown
 */
int vlog_segment_of(vlog_t *vlog, vlog_id_t id, uint64_t *out_number, uint64_t *out_disk_bytes);

#endif /* __VLOG_H__ */
