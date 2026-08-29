/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_DB_H__
#define __TIDESDB_DB_H__

#include <stddef.h>
#include <stdint.h>
#include <time.h>

/* ===== opaque handles ===== */

/* forward-declared so a consumer (FFI bindings, apps) uses them only through pointers; the internal
 * headers define the real struct bodies, so this stays a pure public api surface and the two do not
 * collide when both are visible in one translation unit */
typedef struct tidesdb_t tidesdb_t;
typedef struct tidesdb_column_family_t tidesdb_column_family_t;
typedef struct tidesdb_txn_t tidesdb_txn_t;
typedef struct tidesdb_snapshot_t tidesdb_snapshot_t;
typedef struct tidesdb_iter_t tidesdb_iter_t;

/* ===== enums ===== */

/**
 * tidesdb_log_level_t
 * logging levels, used both as a message severity and as the sink threshold a message must meet or
 * exceed to be emitted; a larger value is more severe, so a higher threshold emits fewer lines
 */
typedef enum
{
    TDB_LOG_NONE = 0,  /* no logging */
    TDB_LOG_TRACE = 1, /* low severity, highly detailed messages for technical debugging */
    TDB_LOG_INFO = 2,  /* standard information describing engine status or operations */
    TDB_LOG_WARN = 3,  /* non-imminent errors that require awareness */
    TDB_LOG_ERROR = 4  /* an operation failed */
} tidesdb_log_level_t;

/**
 * tidesdb_isolation_level_t
 * transaction isolation levels, weakest to strongest
 */
typedef enum
{
    /* every version is visible, including sequences still in progress */
    TDB_ISOLATION_READ_UNCOMMITTED = 0,
    /* the newest committed version, with the ceiling re-read on every operation */
    TDB_ISOLATION_READ_COMMITTED = 1,
    /* the ceiling is frozen when the transaction begins, and a commit validates that every key it
       read still holds the version it read */
    TDB_ISOLATION_REPEATABLE_READ = 2,
    /* frozen ceiling, and a commit reserves each key it writes on a first-committer-wins basis
       rather than validating what it read */
    TDB_ISOLATION_SNAPSHOT = 3,
    /* both of the checks above, plus the one that catches write skew */
    TDB_ISOLATION_SERIALIZABLE = 4
} tidesdb_isolation_level_t;

/**
 * tidesdb_txn_state_t
 * transaction lifecycle state, reported by tidesdb_txn_state for two-phase-commit coordination
 */
typedef enum
{
    TDB_TXN_STATE_ACTIVE = 0,    /* buffering writes, not yet resolved */
    TDB_TXN_STATE_PREPARED = 1,  /* durably prepared under an xid, awaiting commit or rollback */
    TDB_TXN_STATE_COMMITTED = 2, /* committed and applied */
    TDB_TXN_STATE_ABORTED = 3    /* rolled back or expired */
} tidesdb_txn_state_t;

/** compression algorithms.
 * ABI/on-disk contract -- these numeric values are persisted in sstable/vlog metadata and are
 * duplicated in compress.h. the two copies must stay identical -- compress.c _Static_asserts the
 * compress.h copy; keep this copy in lockstep. every enumerator is always defined; whether a
 * backend can actually be used is a build-time choice (the -DTIDESDB_WITH_* options), queryable at
 * runtime via tidesdb_compression_available. the sentinel guard lets this standalone FFI header and
 * the internal compress.h share a translation unit -- whichever is included first defines the type,
 * the other skips; the two blocks are kept textually identical. */
#ifndef TDB_COMPRESSION_ALGORITHM_DEFINED
#define TDB_COMPRESSION_ALGORITHM_DEFINED
typedef enum
{
    TDB_COMPRESS_NONE = 0,
    TDB_COMPRESS_SNAPPY = 1,
    TDB_COMPRESS_LZ4 = 2,
    TDB_COMPRESS_ZSTD = 3,
    TDB_COMPRESS_LZ4_FAST = 4
} tidesdb_compression_algorithm_t;
#endif

/**
 * tidesdb_compression_available
 * whether this build can actually use a compression algorithm. every enumerator above is always
 * defined, but a backend is only linked in when its -DTIDESDB_WITH_* option was set, so a caller
 * choosing one for a column family's encoding pipeline asks here first rather than discovering it
 * when a node fails to decode. TDB_COMPRESS_NONE is always available
 * @param type the algorithm to query
 * @return 1 if this build can compress and decompress with it, 0 otherwise
 */
int tidesdb_compression_available(tidesdb_compression_algorithm_t type);

/**
 * tidesdb_sync_mode_t
 * durability sync modes for the write-ahead log, ordered by what an acknowledged commit has
 * already survived. none does nothing at commit, so a commit can be lost to a crash of this
 * process as well as of the machine; interval and full both put the record in the operating
 * system's hands before returning, so only a machine crash can take it, and full also waits for
 * the device. a clean close loses nothing in any mode
 */
typedef enum
{
    TDB_SYNC_NONE = 0,    /* nothing at commit; fastest, a crash of either kind may lose commits */
    TDB_SYNC_FULL = 1,    /* fsync every commit; slowest, no commit loss on crash */
    TDB_SYNC_INTERVAL = 2 /* fsync on a background interval; bounded loss window */
} tidesdb_sync_mode_t;

/* ===== error codes ===== */

#define TDB_SUCCESS          0
#define TDB_ERR_MEMORY       -1
#define TDB_ERR_INVALID_ARGS -2
#define TDB_ERR_NOT_FOUND    -3
#define TDB_ERR_IO           -4
#define TDB_ERR_CORRUPTION   -5
#define TDB_ERR_EXISTS       -6
#define TDB_ERR_CONFLICT     -7
#define TDB_ERR_TOO_LARGE    -8
#define TDB_ERR_MEMORY_LIMIT -9
#define TDB_ERR_INVALID_DB   -10
#define TDB_ERR_UNKNOWN      -11
/* transient contention, never a failed operation and never data loss -- something else held what
 * the call needed, nothing was written, and the remedy is always to try again. it is not confined
 * to the operations that take a family exclusively: a read has to open sstables and walk sources a
 * compaction may be moving, so any get, existence check or iterator step can report it too. treat
 * it as retry, never as absence and never as an error to surface */
#define TDB_ERR_LOCKED      -12
#define TDB_ERR_READONLY    -13
#define TDB_ERR_TXN_EXPIRED -14
/* the device or filesystem is out of space. distinct from TDB_ERR_IO because it says what to do
 * about it -- the data is intact and the operation succeeds once space is freed, where an io error
 * carries no such promise */
#define TDB_ERR_NO_SPACE -15
/* the transaction was aborted by another thread through tidesdb_txn_request_abort, and every
 * operation on it from that point reports this, its commit included -- except phase two of a
 * transaction that already prepared, which only the coordinator may resolve. distinct from
 * TDB_ERR_CONFLICT on purpose: a
 * conflict is the engine's own first-committer-wins verdict, where this says an outside authority
 * decided the transaction loses and the engine never got a say. a caller layered over the engine --
 * a replication plugin whose cluster certified against this transaction, say -- needs to tell the
 * two apart to report its own verdict rather than the engine's */
#define TDB_ERR_TXN_ABORTED -16

/* the point in time asked for is no longer reconstructable -- a collection has already run below
 * that sequence, so the versions it would resolve to are gone and answering would mean reporting
 * whatever survived instead of what was true */
#define TDB_ERR_TOO_OLD -17

/**
 * tidesdb_strerror
 * a short human-readable description of a result code, for logging and error messages
 * the returned string is a static literal -- it is never NULL, must not be freed, and stays valid
 * for the life of the process. an unrecognised code describes itself as unknown rather than
 * returning NULL, so a caller may pass a result through without checking it first
 * @param code any TDB_SUCCESS or TDB_ERR_* value
 * @return the description, never NULL
 */
const char *tidesdb_strerror(int code);

/* ===== configuration limits ===== */

#define TDB_MAX_CF_NAME_LEN 128

/* maximum number of stacked encodings a column family may apply (compression, encryption, custom)
 */
#define TDB_ENCODING_PIPELINE_MAX 8

/* longest bound tidesdb_txn_delete_range and tidesdb_txn_delete_prefix accept. an interval delete
 * holds its bounds in a fixed slot for the length of its commit, which is what stops a concurrent
 * write landing inside the range; there is no slot big enough for an arbitrary bound, so a longer
 * one is refused rather than silently narrowed. a range too wide to name in one call is expressed
 * as several */
#define TDB_MAX_RANGE_BOUND_SIZE 256

/* keys are ordered byte-wise (memcmp); a caller that wants a different order encodes keys to be
 * memcomparable (big-endian integers, sign-flipped signed integers, inverted bytes for descending),
 * so the engine carries no pluggable comparator. */

/* ===== callback types ===== */

/**
 * tidesdb_commit_op_t
 * one operation in a committed transaction batch, passed to the commit hook
 * @key key data, valid only during the callback invocation
 * @key_size size of key in bytes
 * @value value data, NULL for deletes, valid only during the callback invocation
 * @value_size size of value in bytes, 0 for deletes
 * @ttl the pair's absolute expiry as a unix timestamp -- the deadline the engine stored, not the
 * lifetime in seconds that tidesdb_txn_put was given, so a hook forwarding the write elsewhere
 * reproduces the same expiry instant rather than restarting the clock. -1 when it never expires
 * @is_delete 1 for a delete operation, 0 for a put
 */
typedef struct tidesdb_commit_op_t
{
    const uint8_t *key;
    size_t key_size;
    const uint8_t *value;
    size_t value_size;
    time_t ttl;
    int is_delete;
} tidesdb_commit_op_t;

/**
 * tidesdb_commit_hook_fn
 * invoked synchronously after a transaction commits to a column family, receiving the full batch
 * for that cf atomically. fires after the wal write, memtable apply, and commit-status marking
 * complete; a hook failure is logged but does not roll back the commit (the data is already
 * durable).
 * @param ops committed operations, valid only during the callback invocation
 * @param num_ops number of operations in ops
 * @param commit_seq monotonic commit sequence number
 * @param ctx user context pointer
 * @return 0 on success, non-zero on failure (logged as a warning)
 */
typedef int (*tidesdb_commit_hook_fn)(const tidesdb_commit_op_t *ops, int num_ops,
                                      uint64_t commit_seq, void *ctx);

/* ===== configuration ===== */

/**
 * tidesdb_column_family_config_t
 * per-column-family configuration. every field is mutable at runtime via
 * tidesdb_cf_update_runtime_config, since keys are ordered byte-wise and sstables are therefore
 * always mergeable. all fields except the commit hook are persisted with the cf in the manifest;
 * the commit hook is a runtime-only callback. the memtable, wal, and their sync/skip-list settings
 * are db-level (tidesdb_config_t), not per-cf.
 * @name column family name, the cf's persisted identity
 * @level_size_ratio target size ratio between successive levels
 * @min_levels floor on the level count. the tree deepens as it fills and sheds levels again as
 * data is deleted, and this is the depth it will not shed below -- the engine keeps its own floor
 * of a flush tier plus one level for merges to land in, so a smaller value has no further effect
 * @dividing_level_offset how far above the largest level the dividing level sits, so 1 means
 * X = L - 2. the dividing level is where a merge writes output partitioned to the largest level's
 * file boundaries, which is what lets later merges take one group of overlapping files at a time.
 * 0 puts it directly above the largest level, where a single dividing merge rewrites a tenth of the
 * data at once; larger offsets cut that at the cost of more files open at once
 * @keep_values_inline 1 to hold every value in the klog whatever its size, ignoring the database's
 * value_separation_threshold, 0 to separate by that threshold like every other family. a separated
 * value costs a scan one value-log read per row, so a family that is scanned far more than it is
 * merged can be worth keeping whole even though its values are large. the cost is the one the
 * threshold exists to avoid, that compaction rewrites those bytes on every merge
 * @btree_klog_block_size target size in bytes of a btree klog node. raise it alongside the
 * database's value_separation_threshold rather than on its own. 0 leaves the choice to the btree,
 * whose own default
 * is far larger than the one this config starts at, so a caller who wants the small node size that
 * fits the block manager's first-read window must ask for it rather than pass 0
 * @encoding_pipeline encoding ids applied in order to btree klog nodes and undone in reverse on
 *                    read; the ids are recorded in the sstable footer so a reader rebuilds the same
 *                    chain from the file. a value separated into the shared value log carries the
 *                    same chain, recorded in the value's own block, since compaction moves a value
 *                    forward by id and the sstable referencing it may by then record a different
 *                    pipeline. an id naming no encoding is rejected; one naming
 *                    an algorithm this build lacks is accepted so a database written elsewhere
 * still opens, and fails when such a node is read
 * @encoding_count number of entries in the pipeline, at most TDB_ENCODING_PIPELINE_MAX
 * @enable_bloom_filter build a partition-range filter for point-get pruning
 * @bloom_fpr target bloom false-positive rate when the filter is enabled
 * @default_isolation_level isolation applied to a transaction opened without an explicit level
 * @l1_file_count_trigger L1 sstable count that triggers compaction
 * @tombstone_density_trigger ratio in [0,1] above which an sstable's tombstone density
 *                            (tombstone_count / num_entries) escalates compaction; 0 disables it
 * @tombstone_density_min_entries minimum entry count for an sstable to be judged by the density
 *                                trigger, filtering tiny-sstable noise; 0 imposes no minimum, so
 *                                every sstable is judged by density however small it is
 * @commit_hook_fn optional post-commit callback, runtime-only, NULL to disable
 * @commit_hook_ctx user context passed to the commit hook, runtime-only
 */
typedef struct tidesdb_column_family_config_t
{
    char name[TDB_MAX_CF_NAME_LEN];
    size_t level_size_ratio;
    int min_levels;
    int dividing_level_offset;
    int keep_values_inline;
    size_t btree_klog_block_size;
    uint8_t encoding_pipeline[TDB_ENCODING_PIPELINE_MAX];
    uint8_t encoding_count;
    int enable_bloom_filter;
    double bloom_fpr;
    tidesdb_isolation_level_t default_isolation_level;
    int l1_file_count_trigger;
    double tombstone_density_trigger;
    uint64_t tombstone_density_min_entries;
    tidesdb_commit_hook_fn commit_hook_fn;
    void *commit_hook_ctx;
} tidesdb_column_family_config_t;

/**
 * tidesdb_config_t
 * database-level configuration. the memtable, write-ahead log, block cache, and worker pool are
 * db-level and shared by every column family, so their settings live here rather than per-cf.
 * @db_path path to the database directory
 * @num_flush_threads number of flush worker threads
 * @num_compaction_threads number of compaction worker threads
 * @log_level minimum severity to emit
 * @block_cache_size size in bytes of the db-level block cache for hot sstable blocks
 * @max_open_sstables maximum number of concurrently open sstable file handles. lowered at open to
 * what this process's open-file ceiling leaves once the manifest, stdio and temporaries are
 * allowed for, and a lowering says so in the log at warn -- raise the ceiling with
 * tidesdb_raise_open_file_limit first if the larger figure is the one you want
 * @log_to_file 1 to write the log to tidesdb.log inside db_path, 0 for stderr. the sink is
 * process-wide rather than per-database, so the last database opened with this set owns it and
 * every other handle in the process logs there too, until that one closes
 * @log_truncation_at size in bytes past which the log file is truncated and reopened, 0 for
 * never; ignored unless log_to_file is set
 * @memtable_write_buffer_size memory the active memtable may occupy before it is rotated, 0 for
 * auto. this is a memory budget rather than a promise about the size of what a rotation flushes --
 * an entry costs its key and value plus about a hundred bytes of skip list node, pointer arrays
 * and version struct, so a memtable of small entries reaches this limit holding far fewer bytes of
 * data than the limit names. the overhead is fixed per entry, so it is most of an entry that holds
 * a short value and almost none of one that holds a large one
 * @memtable_skip_list_max_level skip list max level for the memtable, 0 for the default
 * (12)
 * @memtable_skip_list_probability skip list level probability, 0 for the default (0.25)
 * @memtable_sync_mode durability mode for the write-ahead log
 * @memtable_sync_interval_us fsync interval for TDB_SYNC_INTERVAL, in microseconds; 0 uses a one
 * second default, and the field is ignored under the other sync modes
 * @value_separation_threshold values at or above this size are stored in the shared value log and
 * referenced from the key log, so a value stays inline only while it is strictly under it; 0
 * selects the default. it is database level because the value log is one shared structure, and
 * because the decision keys on the size of a value rather than on which family holds it, so one
 * cut-off serves a family of small metadata and a family of large blobs alike. raising it keeps
 * larger values inline, which spares a scan or a get the second read the value log costs and
 * charges compaction with rewriting those bytes on every merge. keep it at or under a quarter of a
 * family's btree_klog_block_size -- an inlined value approaching the node size leaves a node
 * holding one entry and spends the btree fan-out that makes a lookup cheap. the pairing is
 * advisory, and a config that breaks it only logs a warning. a single family can opt out entirely
 * with keep_values_inline
 * @vlog_segment_size size at which the value log seals its active segment and opens a fresh one,
 * in bytes; 0 selects the default. a reclaim drains every segment worth draining, so this does not
 * change how much space the store settles at -- it changes what reclaiming costs. smaller segments
 * mean more of them and more live data copied forward per reclaim, measurably slower below 256 MiB;
 * larger ones are close to flat
 * @memtable_l0_queue_stall_threshold immutable-queue depth at which writes stall for
 * backpressure, or 0 to never stall. left at 0 the queue is unbounded and a writer outrunning
 * the flush threads is never paced, so it is a value to set deliberately rather than leave
 * @memtable_idle_flush_seconds how long the active memtable may sit unwritten before the engine
 * rotates it on its own, or 0 to never do so. a database that stops taking writes otherwise holds
 * that data in memory indefinitely -- its log cannot be unlinked until it reaches L1, so recovery
 * stays long, reads keep paying for it, and compaction never sees the shape it would act on.
 * rotating on idle is a write a quiet process would not otherwise make, which is why it can be
 * turned off
 * @txn_timeout_seconds how long a transaction may stay active before the next operation on it
 * expires it, or 0 for no timeout, which is the default. an abandoned transaction holds its
 * snapshot and its write reservations, which keeps the reclamation floor down and stops compaction
 * dropping old versions, so a caller that may leak transactions should bound them. a single
 * transaction can override this with tidesdb_txn_set_timeout
 */
typedef struct tidesdb_config_t
{
    char *db_path;
    int num_flush_threads;
    int num_compaction_threads;
    tidesdb_log_level_t log_level;
    size_t block_cache_size;
    size_t max_open_sstables;
    int log_to_file;
    size_t log_truncation_at;
    size_t memtable_write_buffer_size;
    int memtable_skip_list_max_level;
    float memtable_skip_list_probability;
    int memtable_sync_mode;
    uint64_t memtable_sync_interval_us;
    size_t value_separation_threshold;
    size_t vlog_segment_size;
    int memtable_l0_queue_stall_threshold;
    int memtable_idle_flush_seconds;
    int64_t txn_timeout_seconds;
} tidesdb_config_t;

/* ===== statistics ===== */

/* the maximum number of sstable levels a column family keeps; per-level stat arrays are sized to
 * this, so a stats struct needs no heap allocation. it must equal the engine's internal level cap,
 * which a compile-time assert in the engine enforces */
#define TDB_MAX_LEVELS 8

/**
 * tidesdb_cf_stats_t
 * per-column-family statistics returned by tidesdb_get_cf_stats; a flat value the caller owns, with
 * no heap members and nothing to free. shared-memtable figures are db-level and live in
 * tidesdb_db_stats_t
 * @num_levels number of levels in the cf
 * @config a copy of the cf configuration
 * @level_sizes on-disk size of each level, indexed by level-1, valid for the first num_levels
 * entries
 * @level_num_sstables sstable count of each level, indexed by level-1
 * @level_key_counts key count of each level, indexed by level-1
 * @level_tombstone_counts tombstone count of each level, indexed by level-1
 * @total_keys total distinct keys across every sstable in the cf
 * @total_data_size the family's own on-disk size, the sum of its key logs, which is also the sum
 * of level_sizes. values below the spill threshold are inside those bytes already; what spilled
 * lives in the shared value log, whose size is database-level and reported as vlog_file_size
 * @avg_key_size average key length in bytes, over distinct keys
 * @avg_value_size average value length in bytes, over distinct keys (tombstones contribute zero)
 * @read_amp point-lookup read amplification, the sstables a worst-case get may probe
 * @btree_total_nodes total btree nodes across the cf
 * @btree_max_height maximum btree height
 * @btree_avg_height average btree height
 * @total_tombstones sum of tombstone_count across every sstable
 * @tombstone_ratio total_tombstones / total_keys, 0 when total_keys is 0
 * @max_sst_density worst per-sstable tombstone density observed
 * @max_sst_density_level 1-based level where max_sst_density was observed, 0 if none
 * @wal_bytes_written this family's share of the shared write-ahead log, as the encoded size of
 * its own entries. an attribution rather than a measurement -- the batch header and the block
 * framing belong to no single family, so these do not sum to what the log wrote; the database
 * level figure of the same name is the measured one
 * @flush_bytes_written on-disk bytes this cf's flushes wrote to L1
 * @compaction_bytes_written on-disk bytes this cf's compactions wrote
 * @compaction_bytes_read on-disk bytes this cf's compactions read as input
 * @user_bytes_written logical key+value bytes committed to this cf
 * @compaction_count compactions this cf has run
 * @unflushed_key_count distinct keys resident in the shared memtables for this cf and not yet in
 * any sstable, so total_keys plus this is the live logical key count including what is still in
 * memory
 */
typedef struct tidesdb_cf_stats_t
{
    int num_levels;
    tidesdb_column_family_config_t config;
    size_t level_sizes[TDB_MAX_LEVELS];
    int level_num_sstables[TDB_MAX_LEVELS];
    uint64_t level_key_counts[TDB_MAX_LEVELS];
    uint64_t level_tombstone_counts[TDB_MAX_LEVELS];
    uint64_t total_keys;
    uint64_t total_data_size;
    double avg_key_size;
    double avg_value_size;
    double read_amp;
    uint64_t btree_total_nodes;
    uint32_t btree_max_height;
    double btree_avg_height;
    uint64_t total_tombstones;
    double tombstone_ratio;
    double max_sst_density;
    int max_sst_density_level;
    uint64_t wal_bytes_written;
    uint64_t flush_bytes_written;
    uint64_t compaction_bytes_written;
    uint64_t compaction_bytes_read;
    uint64_t user_bytes_written;
    uint64_t compaction_count;
    uint64_t unflushed_key_count;
} tidesdb_cf_stats_t;

/**
 * tidesdb_cache_stats_t
 * db-level block cache statistics returned by tidesdb_get_cache_stats
 * @enabled 1 if the block cache is enabled
 * @total_entries number of cached entries
 * @total_bytes bytes used by the cache
 * @hits cache hits
 * @misses cache misses
 * @hit_rate hits / (hits + misses)
 * @num_partitions number of cache shards
 */
typedef struct tidesdb_cache_stats_t
{
    int enabled;
    size_t total_entries;
    size_t total_bytes;
    uint64_t hits;
    uint64_t misses;
    double hit_rate;
    size_t num_partitions;
} tidesdb_cache_stats_t;

/* the most encoding chains reported separately, for either the key logs or the value log */
#define TDB_MAX_ENCODING_CHAINS 16

/**
 * tidesdb_encoding_stats_t
 * what one encoding chain achieved on the data it wrote. reported per chain rather than per column
 * family because a family can change its codec, and compaction rewrites data under whichever
 * pipeline is merging it, so a single figure for a family would average across settings that no
 * longer apply and describe none of them
 * @ids the codec ids in the order applied, empty when the data was stored verbatim
 * @id_count how many ids
 * @logical_bytes what the data amounts to before encoding
 * @stored_bytes what it occupies on disk, so logical over stored is the realised ratio
 * @item_count values for the value log, sstables for the key logs
 */
typedef struct
{
    uint8_t ids[TDB_ENCODING_PIPELINE_MAX];
    int id_count;
    uint64_t logical_bytes;
    uint64_t stored_bytes;
    uint64_t item_count;
} tidesdb_encoding_stats_t;

/**
 * tidesdb_db_stats_t
 * database-level statistics returned by tidesdb_get_db_stats. the memtable, the value log, and the
 * mvcc clock are db-level and shared, so their figures live here.
 * @num_column_families number of column families
 * @immutable_memtable_count immutable memtables awaiting flush (the L0 queue depth)
 * @compaction_pending_count compaction jobs queued for the worker pool
 * @total_sstable_count total sstables across every cf and level
 * @total_data_size_bytes on-disk key-log bytes summed across every cf and level, the database-wide
 * counterpart of the per-family total_data_size. the value log is reported separately as
 * vlog_file_size, since it is shared rather than owned by any one family
 * @num_open_sstables currently open sstable file handles
 * @global_seq current db-global sequence number (the mvcc clock)
 * @min_snapshot_seq the oldest live-transaction snapshot, the compaction gc floor
 * @active_txn_count live transactions joined to the registry, which is repeatable-read and
 * stronger only -- read-uncommitted and read-committed transactions need no snapshot reservation
 * and so are not counted, and read-committed is the default
 * @txn_memory_bytes bytes held by in-flight transactions, over the same registered set
 * @memtable_bytes memory the active memtable occupies, the figure memtable_write_buffer_size is
 * compared against, so it counts skip list nodes and version structs as well as key and value
 * bytes
 * @is_flushing 1 while an immutable is queued or flushing
 * @next_cf_index next column family id to be assigned
 * @wal_generation current write-ahead-log generation counter
 * @flush_count sstables flushed across every cf
 * @compaction_count compactions run across every cf
 * @flush_bytes_written flush output bytes summed across every cf
 * @compaction_bytes_written compaction output bytes summed across every cf
 * @compaction_bytes_read compaction input bytes summed across every cf
 * @wal_bytes_written framed write-ahead-log bytes, counted at the append. the log is one shared
 * structure for the whole database rather than one per family, so this is measured there rather
 * than summed from the families, whose own figure is an attribution and excludes the batch header
 * and the block framing. the log is reclaimed with its memtable and never appears in the on-disk
 * totals, but the device was still asked to write it, and a write-amplification figure that omits
 * it understates by a whole copy of the data
 * @user_bytes_written logical committed bytes summed across every cf
 * @vlog_file_size total value-log file size in bytes
 * @vlog_value_count values currently indexed in the value log
 * @vlog_used_bytes uncompressed length the indexed values represent. this counts everything the
 * index still names, reachable or not, so it is not a measure of live data
 * @vlog_stored_bytes the on-disk length those same indexed values occupy. read against
 * vlog_used_bytes it is the encoding pipeline's realised ratio, measured on the data the store is
 * actually holding rather than on a sample: used over stored is how much the values shrank
 * @vlog_live_bytes value-log bytes the live sstables still reference, summed from what each records
 * about the segments its separated values landed in. this is the figure space amplification is
 * against: a store can hold many gigabytes of values no tree can reach, and only this tells them
 * apart from the ones still worth keeping
 * @vlog_segment_count value-log segment files currently open, the one taking appends included
 * @vlog_bytes_written value-log bytes ever appended, reclamation's own rewrites included. this is
 * the term a write-amplification figure needs from the log -- the live and stored totals describe
 * what is held now, and on a store that separates its values most of the writing happens here
 * @vlog_dead_bytes value-log bytes beyond what the live values account for, the space a reclaim
 * could recover
 * @vlog_reclaim_calls value-log reclaims attempted, lifetime. read beside vlog_reclaim_passes this
 * separates a reclaim that never runs from one that runs and finds nothing worth draining
 * @vlog_reclaim_passes value-log reclaim passes that drained a segment, since this handle opened
 * @vlog_segments_retired value-log segment files a reclaim has unlinked
 * @vlog_segments_drainable sealed segments holding so little live data that rewriting the tables
 * referencing them would free most of a file. read against vlog_dead_bytes this says how much of
 * the garbage is currently actionable, and a figure that stays high is reclamation falling behind
 * @writes_throttled commits the L0 admission policy made dwell before admitting
 * @writes_blocked commits the L0 admission policy made wait for the flush queue to drain
 * @write_stall_us total microseconds commits were held in L0 admission, dwell plus wait
 * @write_stall_ceiling_hits commits admitted only because the admission wait ceiling expired; any
 * of these means flush did not keep up with ingestion
 */
typedef struct tidesdb_db_stats_t
{
    int num_column_families;
    int immutable_memtable_count;
    int compaction_pending_count;
    int total_sstable_count;
    uint64_t total_data_size_bytes;
    int num_open_sstables;
    uint64_t global_seq;
    uint64_t min_snapshot_seq;
    int active_txn_count;
    int64_t txn_memory_bytes;
    size_t memtable_bytes;
    int is_flushing;
    uint32_t next_cf_index;
    uint64_t wal_generation;
    uint64_t flush_count;
    uint64_t compaction_count;
    uint64_t flush_bytes_written;
    uint64_t compaction_bytes_written;
    uint64_t compaction_bytes_read;
    uint64_t wal_bytes_written;
    uint64_t user_bytes_written;
    uint64_t vlog_file_size;
    uint64_t vlog_value_count;
    uint64_t vlog_used_bytes;
    uint64_t vlog_stored_bytes;
    uint64_t vlog_live_bytes;
    uint64_t vlog_segment_count;
    uint64_t vlog_bytes_written;
    uint64_t vlog_dead_bytes;
    uint64_t vlog_reclaim_calls;
    uint64_t vlog_reclaim_passes;
    uint64_t vlog_segments_retired;
    uint64_t vlog_segments_drainable;
    uint64_t writes_throttled;
    uint64_t writes_blocked;
    uint64_t write_stall_us;
    uint64_t write_stall_ceiling_hits;
} tidesdb_db_stats_t;

/* ===== defaults ===== */

/**
 * tidesdb_default_column_family_config
 * a column family configuration filled with sensible defaults for the caller to adjust
 * @return the default column family configuration by value
 */
tidesdb_column_family_config_t tidesdb_default_column_family_config(void);

/**
 * tidesdb_default_config
 * a database configuration filled with sensible defaults for the caller to adjust
 * @return the default database configuration by value
 */
tidesdb_config_t tidesdb_default_config(void);

/* ===== process limits ===== */

/**
 * tidesdb_raise_open_file_limit
 * raise this process's open-file ceiling toward desired descriptors so a database can keep more
 * sstables open. tidesdb reads the ceiling at open and lowers max_open_sstables to fit it, so an
 * over-large setting costs descriptors it never gets rather than failing opens -- raising the
 * ceiling is what actually buys them, and it is this call, made before tidesdb_open. an explicit,
 * opt-in operator action -- tidesdb never raises the limit itself, only reads it. POSIX
 * raises the RLIMIT_NOFILE soft limit toward the hard limit; Windows raises the CRT stdio cap (max
 * 8192). a failed or partial raise is non-fatal.
 * @param desired target descriptor count; <= 0 just reports the current ceiling
 * @return the open-file ceiling in effect after the attempt
 */
long tidesdb_raise_open_file_limit(long desired);

/* ===== database lifecycle ===== */

/**
 * tidesdb_open
 * open or create a database at config->db_path, recovering the manifest, sstables, and write-ahead
 * log, and starting the worker pool. a manifest that will not read back is self-healed from the
 * sstables on disk rather than failing the open, and says so in the log at warn level
 * @param config database configuration, borrowed -- everything needed is copied, db_path included.
 * a field left at zero is resolved to its default rather than taken literally, for the thread
 * counts, block_cache_size, max_open_sstables, vlog_segment_size, memtable_write_buffer_size,
 * memtable_skip_list_max_level and memtable_skip_list_probability; the rest are used as given,
 * memtable_sync_mode included, where zero is the meaningful value TDB_SYNC_NONE
 * @param db out -- the open database handle on success, untouched on failure
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS on a bad argument or an unformattable path,
 * TDB_ERR_LOCKED when another handle already holds the directory -- a second open from this
 * process or from any other -- TDB_ERR_MEMORY, TDB_ERR_IO if the directory, manifest, value log or
 * a wal could not be opened, or TDB_ERR_CORRUPTION on a column family config that does not decode
 */
int tidesdb_open(const tidesdb_config_t *config, tidesdb_t **db);

/**
 * tidesdb_close
 * flush, quiesce the workers, and free a database handle. the shutdown path reports no status, so
 * this cannot fail for a live handle -- an io error while writing the last of the data is logged,
 * not returned. a caller that needs its data on the device asks for that before closing, with
 * tidesdb_sync_wal, tidesdb_checkpoint, or by running under TDB_SYNC_FULL
 * @param db database handle; no other thread may be inside a call on it, and every transaction and
 * iterator derived from it must already be freed
 * @return TDB_SUCCESS, or TDB_ERR_INVALID_ARGS if db is NULL
 */
int tidesdb_close(tidesdb_t *db);

/* ===== column families ===== */

/**
 * tidesdb_create_column_family
 * create a column family and register it in the manifest
 * @param db database handle
 * @param name column family name
 * @param config column family configuration, borrowed; its name field is ignored, since the name
 * argument is authoritative and is stamped onto the stored config
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS on a bad argument or a config that fails validation,
 * TDB_ERR_INVALID_DB if the database is closing, TDB_ERR_EXISTS, TDB_ERR_MEMORY, or TDB_ERR_IO
 */
int tidesdb_create_column_family(tidesdb_t *db, const char *name,
                                 const tidesdb_column_family_config_t *config);

/**
 * tidesdb_drop_column_family
 * drop a column family by name, deleting its sstables and manifest records. waits out any
 * compaction already running on the family, so a heavily compacting family takes longer to drop.
 * destroys data and cannot be undone, and any handle held for the family is invalid afterwards
 * @param db database handle
 * @param name column family name
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_NOT_FOUND, or TDB_ERR_IO
 */
int tidesdb_drop_column_family(tidesdb_t *db, const char *name);

/**
 * tidesdb_rename_column_family
 * atomically rename a column family. the family is claimed against the compaction scheduler, the
 * whole database memtable is flushed (it is shared, so this is not just this family's data), and
 * new flushes are frozen while the directory moves and the family reloads. the claim is a bounded
 * wait, not an indefinite one
 * @param db database handle
 * @param old_name current name of the column family
 * @param new_name new name for the column family
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_NOT_FOUND, TDB_ERR_EXISTS, TDB_ERR_LOCKED if
 * the family stayed under compaction for the whole quiesce window, or TDB_ERR_IO
 */
int tidesdb_rename_column_family(tidesdb_t *db, const char *old_name, const char *new_name);

/**
 * tidesdb_clone_column_family
 * clone a column family to a new name, copying its sstables. the source is claimed against the
 * compaction scheduler and the whole database memtable is flushed first, so the copy carries
 * everything written before the call rather than only what had already reached disk. the result is
 * a point-in-time copy -- later writes to the source do not appear in it
 * @param db database handle
 * @param src_name source column family name
 * @param dst_name new cloned column family name
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_NOT_FOUND, TDB_ERR_EXISTS, TDB_ERR_LOCKED if
 * the source stayed under compaction for the whole quiesce window, TDB_ERR_MEMORY, or TDB_ERR_IO
 */
int tidesdb_clone_column_family(tidesdb_t *db, const char *src_name, const char *dst_name);

/**
 * tidesdb_get_column_family
 * look up a column family handle by name
 * @param db database handle
 * @param name column family name
 * @return the column family handle, or NULL if not found
 */
tidesdb_column_family_t *tidesdb_get_column_family(tidesdb_t *db, const char *name);

/**
 * tidesdb_list_column_families
 * list the names of every column family
 * @param db database handle
 * @param names out -- a newly allocated array of newly allocated names; the caller frees each name
 * and then the array itself with tidesdb_free. NULL with a count of 0 when there are no families
 * @param count out -- the number of names
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, or TDB_ERR_MEMORY
 */
int tidesdb_list_column_families(tidesdb_t *db, char ***names, int *count);

/**
 * tidesdb_cf_update_runtime_config
 * apply a new configuration to a column family at runtime; every field may change, since byte-wise
 * key ordering keeps all sstables mergeable. the family name and id are preserved (a rename is
 * separate)
 * @param db database handle
 * @param cf column family handle
 * @param new_config the configuration to apply, borrowed; its name field is ignored
 * @param persist_to_disk 1 to persist the new config in the manifest, 0 to apply in memory only
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_LOCKED, or TDB_ERR_IO
 */
int tidesdb_cf_update_runtime_config(tidesdb_t *db, tidesdb_column_family_t *cf,
                                     const tidesdb_column_family_config_t *new_config,
                                     int persist_to_disk);

/**
 * tidesdb_cf_set_commit_hook
 * set or clear a column family's commit hook at runtime
 * @param db database handle
 * @param cf column family handle
 * @param fn commit hook callback, or NULL to disable
 * @param ctx user context passed to the callback
 * @return TDB_SUCCESS, or TDB_ERR_INVALID_ARGS on a NULL db or cf
 */
int tidesdb_cf_set_commit_hook(tidesdb_t *db, tidesdb_column_family_t *cf,
                               tidesdb_commit_hook_fn fn, void *ctx);

/* ===== transactions ===== */

/**
 * tidesdb_txn_begin
 * begin a transaction at the database default isolation level
 * @param db database handle
 * @param txn out -- the new transaction
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS on a NULL db or txn, TDB_ERR_INVALID_DB when the
 * database is closing, or TDB_ERR_MEMORY
 */
int tidesdb_txn_begin(tidesdb_t *db, tidesdb_txn_t **txn);

/**
 * tidesdb_txn_begin_with_isolation
 * begin a transaction at an explicit isolation level
 * @param db database handle
 * @param isolation isolation level
 * @param txn out -- the new transaction
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS on a NULL db or txn or an isolation outside the
 * enum, TDB_ERR_INVALID_DB when the database is closing, or TDB_ERR_MEMORY
 */
int tidesdb_txn_begin_with_isolation(tidesdb_t *db, tidesdb_isolation_level_t isolation,
                                     tidesdb_txn_t **txn);

/**
 * tidesdb_snapshot_create
 * name the database as it stands now, so it can be read again later. the snapshot holds the
 * reclamation floor at its own sequence for as long as it lives, which is what keeps the versions
 * it resolves to from being compacted away -- and is also its cost, the same cost a long-running
 * transaction has. release it as soon as the point in time is no longer wanted
 * @param db database handle
 * @param snapshot out -- the new snapshot
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS on a NULL db or snapshot, TDB_ERR_INVALID_DB when the
 * database is closing, or TDB_ERR_MEMORY
 */
int tidesdb_snapshot_create(tidesdb_t *db, tidesdb_snapshot_t **snapshot);

/**
 * tidesdb_snapshot_release
 * release a snapshot and the reclamation floor it was holding. every transaction opened against it
 * must be freed first, since they read versions only this snapshot keeps alive
 * @param snapshot the snapshot, may be NULL
 */
void tidesdb_snapshot_release(tidesdb_snapshot_t *snapshot);

/**
 * tidesdb_snapshot_seq
 * the sequence a snapshot reads at, for reporting and for comparing against min_snapshot_seq
 * @param snapshot the snapshot
 * @return the sequence, or 0 when snapshot is NULL
 */
uint64_t tidesdb_snapshot_seq(const tidesdb_snapshot_t *snapshot);

/**
 * tidesdb_txn_begin_at_snapshot
 * begin a transaction whose reads resolve as of a snapshot rather than as of now -- the same keys,
 * the same families, answered as they stood when the snapshot was taken. the snapshot must outlive
 * the transaction, because it is what holds the floor under the versions being read.
 *
 * there is no form of this that takes a bare sequence. a sequence below the floor no longer has its
 * versions on disk, and reading there would answer from whatever survived compaction rather than
 * from what was true -- absent for a key that existed, most often. requiring a snapshot taken in
 * advance is what makes the answer trustworthy rather than merely available
 * @param db database handle
 * @param snapshot the snapshot to read at
 * @param txn out -- the new transaction
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS on a NULL argument, TDB_ERR_INVALID_DB when the
 * database is closing, or TDB_ERR_MEMORY
 */
int tidesdb_txn_begin_at_snapshot(tidesdb_t *db, tidesdb_snapshot_t *snapshot, tidesdb_txn_t **txn);

/**
 * tidesdb_txn_begin_at_seq
 * begin a transaction reading as of an explicit sequence, for a point in time no snapshot was taken
 * at -- a sequence read back from tidesdb_txn_read_snapshot, or one recorded elsewhere.
 *
 * it refuses rather than approximates. the versions an older point resolves to survive only while
 * the reclamation floor sits at or below it, and once a collection has run past that sequence a
 * merge has kept one version per key and dropped the rest. reading there would answer from what
 * survived instead of from what was true -- usually reporting a key that existed as absent -- so
 * that case returns TDB_ERR_TOO_OLD and reads nothing.
 *
 * a sequence is therefore readable while something holds the floor under it: an open transaction,
 * or a snapshot taken in advance with tidesdb_snapshot_create. on a database with no reader
 * registered the floor is free to rise, and a sequence stops being reconstructable as soon as it
 * does
 * @param db database handle
 * @param seq the sequence to read at
 * @param txn out -- the new transaction
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS on a NULL db or txn, TDB_ERR_TOO_OLD when a collection
 * has already run below seq, TDB_ERR_INVALID_DB when the database is closing, or TDB_ERR_MEMORY
 */
int tidesdb_txn_begin_at_seq(tidesdb_t *db, uint64_t seq, tidesdb_txn_t **txn);

/**
 * tidesdb_oldest_readable_seq
 * the oldest sequence tidesdb_txn_begin_at_seq will still accept -- the highest reclamation floor
 * any collection has taken. it only ever rises, and a snapshot or an open transaction is what keeps
 * it from rising past a point still wanted
 * @param db database handle
 * @return the oldest readable sequence, or 0 when db is NULL
 */
uint64_t tidesdb_oldest_readable_seq(const tidesdb_t *db);

/**
 * tidesdb_txn_begin_cf
 * begin a transaction at the given column family's default isolation level
 * @param db database handle
 * @param cf column family whose default isolation to use
 * @param txn out -- the new transaction
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS on a NULL db, cf or txn, TDB_ERR_INVALID_DB when the
 * database is closing, or TDB_ERR_MEMORY
 */
int tidesdb_txn_begin_cf(tidesdb_t *db, tidesdb_column_family_t *cf, tidesdb_txn_t **txn);

/**
 * tidesdb_txn_put
 * buffer a put into a transaction
 * @param txn transaction
 * @param cf target column family
 * @param key key data
 * @param key_size size of key in bytes
 * @param value value data; may be empty, which stores the key present carrying nothing. that is a
 * distinct state from an absence -- a read returns it with a zero size rather than reporting the
 * key missing, and tidesdb_txn_delete remains the way to make a key absent
 * @param value_size size of value in bytes; zero is allowed
 * @param ttl how long the entry lives, in seconds from now; zero or negative never expires. the
 * engine converts it to an absolute deadline once, here at the boundary, and stores that -- so a
 * long recovery cannot extend an entry's life, and expiry stays one comparison against the clock
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS on a NULL txn, cf or key, TDB_ERR_TXN_EXPIRED once a
 * timeout has passed, or TDB_ERR_MEMORY
 */
int tidesdb_txn_put(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *key,
                    size_t key_size, const uint8_t *value, size_t value_size, time_t ttl);

/**
 * tidesdb_txn_get
 * read a key at the transaction snapshot, recording the read into the conflict footprint
 * @param txn transaction
 * @param cf target column family
 * @param key key data
 * @param key_size size of key in bytes
 * @param value out -- newly allocated value the caller frees
 * @param value_size out -- size of value in bytes
 * @return TDB_SUCCESS, TDB_ERR_NOT_FOUND, TDB_ERR_TXN_EXPIRED if a timeout has passed,
 * TDB_ERR_LOCKED if contention left the read unservable and it should be retried,
 * TDB_ERR_INVALID_ARGS on a NULL txn or cf, or TDB_ERR_MEMORY, TDB_ERR_IO or TDB_ERR_CORRUPTION
 * from a source read
 */
int tidesdb_txn_get(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *key,
                    size_t key_size, uint8_t **value, size_t *value_size);

/**
 * tidesdb_txn_get_notrack
 * read a key at the transaction snapshot without recording it into the conflict footprint, for
 * existence probes (such as primary-key uniqueness) that should not pollute the write-write base
 * @param txn transaction
 * @param cf target column family
 * @param key key data
 * @param key_size size of key in bytes
 * @param value out -- newly allocated value the caller frees
 * @param value_size out -- size of value in bytes
 * @return TDB_SUCCESS, TDB_ERR_NOT_FOUND, TDB_ERR_TXN_EXPIRED if a timeout has passed,
 * TDB_ERR_LOCKED if contention left the read unservable and it should be retried,
 * TDB_ERR_INVALID_ARGS on a NULL txn or cf, or TDB_ERR_MEMORY, TDB_ERR_IO or TDB_ERR_CORRUPTION
 * from a source read
 */
int tidesdb_txn_get_notrack(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *key,
                            size_t key_size, uint8_t **value, size_t *value_size);

/**
 * tidesdb_txn_read_snapshot
 * the sequence ceiling this transaction's reads filter at, so a caller can reason about which
 * committed versions the transaction can and cannot see
 * @param txn the transaction
 * @return the read snapshot sequence -- UINT64_MAX for read-uncommitted, the current sequence for
 *         read-committed, and the sequence frozen at begin for repeatable-read and stronger; 0 on
 * NULL
 */
uint64_t tidesdb_txn_read_snapshot(const tidesdb_txn_t *txn);

/**
 * tidesdb_txn_contains
 * non-tracking existence check at the transaction snapshot
 * @param txn transaction
 * @param cf target column family
 * @param key key data
 * @param key_size size of key in bytes
 * @return TDB_SUCCESS if present, TDB_ERR_NOT_FOUND if absent, TDB_ERR_TXN_EXPIRED if a timeout has
 * passed, TDB_ERR_LOCKED if contention left the read unservable and it should be retried, or an
 * error code
 */
int tidesdb_txn_contains(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *key,
                         size_t key_size);

/**
 * tidesdb_txn_delete_range
 * buffer a delete of every key in the column family from lo (inclusive) to hi (exclusive). it costs
 * one entry however many keys it covers, and it deletes keys written before it as well as keys
 * written after it -- so it is not the same as deleting the keys that happen to be there when you
 * call it. a write to a key inside the range survives it when it is newer: buffered after it in the
 * same transaction, or committed at a later sequence
 *
 * the delete is O(1) to write but not to reclaim: the keys it covers stay on disk until a
 * compaction rewrites the range, and reads pay a bounded interval lookup until then
 *
 * at TDB_ISOLATION_SNAPSHOT and above the commit is refused with TDB_ERR_CONFLICT when any key in
 * the range was written after this transaction drew its snapshot, and a write to a key inside a
 * range another transaction is deleting is refused the same way
 *
 * each bound is at most TDB_MAX_RANGE_BOUND_SIZE bytes. the bound is held in a fixed slot for the
 * length of the commit, which is what stops a concurrent write landing inside the range; a longer
 * one is refused here rather than at the commit
 * @param txn transaction
 * @param cf target column family
 * @param lo inclusive lower bound; must not be empty. keys are never empty, so a single zero byte
 * is a lower bound below every key there can be
 * @param lo_size size of lo in bytes, greater than zero and at most TDB_MAX_RANGE_BOUND_SIZE
 * @param hi exclusive upper bound, or NULL with hi_size 0 to run to the end of the family
 * @param hi_size size of hi in bytes, at most TDB_MAX_RANGE_BOUND_SIZE, 0 for the end of the family
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS on a NULL txn, cf or lo, an empty lower bound or a
 * bound past TDB_MAX_RANGE_BOUND_SIZE, TDB_ERR_TXN_EXPIRED once a timeout has passed, or
 * TDB_ERR_MEMORY
 */
int tidesdb_txn_delete_range(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *lo,
                             size_t lo_size, const uint8_t *hi, size_t hi_size);

/**
 * tidesdb_txn_delete_prefix
 * buffer a delete of every key in the column family that begins with prefix. it costs one entry
 * however many keys it covers, and it deletes keys written before it as well as keys written after
 * it -- so it is not the same as deleting the keys that happen to be there when it is buffered. a
 * write to a key under the prefix, buffered after this in the same transaction or committed at a
 * later sequence, survives it
 *
 * the delete is O(1) to write but not to reclaim: the keys it covers stay on disk until a
 * compaction rewrites the range, and reads pay a bounded interval lookup until then
 *
 * at TDB_ISOLATION_SNAPSHOT and above the commit is refused with TDB_ERR_CONFLICT when any key
 * under the prefix was written after this transaction drew its snapshot, and a write to a key under
 * a prefix another transaction is deleting is refused the same way. a two-phase transaction holds
 * its prefix from the prepare until phase two resolves it, so a write under it is refused for as
 * long as it stays in doubt
 *
 * the prefix is at most TDB_MAX_RANGE_BOUND_SIZE bytes, for the reason given on
 * tidesdb_txn_delete_range, which this is the one-bound form of
 * @param txn transaction
 * @param cf target column family
 * @param prefix the prefix to delete under; must not be empty, since a whole family is dropped with
 * tidesdb_drop_column_family rather than deleted a prefix at a time
 * @param prefix_size size of prefix in bytes, greater than zero and at most
 * TDB_MAX_RANGE_BOUND_SIZE
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS on a NULL txn, cf or prefix, an empty prefix or one
 * past TDB_MAX_RANGE_BOUND_SIZE, TDB_ERR_TXN_EXPIRED once a timeout has passed, or TDB_ERR_MEMORY
 */
int tidesdb_txn_delete_prefix(tidesdb_txn_t *txn, tidesdb_column_family_t *cf,
                              const uint8_t *prefix, size_t prefix_size);

/**
 * tidesdb_txn_delete
 * buffer a delete (tombstone) into a transaction
 * @param txn transaction
 * @param cf target column family
 * @param key key data
 * @param key_size size of key in bytes
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS on a NULL txn, cf or key, TDB_ERR_TXN_EXPIRED once a
 * timeout has passed, or TDB_ERR_MEMORY
 */
int tidesdb_txn_delete(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *key,
                       size_t key_size);

/**
 * tidesdb_txn_single_delete
 * buffer a single-delete, a tombstone the caller promises supersedes at most one put, so the two
 * can be reaped together at compaction
 * @param txn transaction
 * @param cf target column family
 * @param key key data
 * @param key_size size of key in bytes
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS on a NULL txn, cf or key, TDB_ERR_TXN_EXPIRED once a
 * timeout has passed, or TDB_ERR_MEMORY
 */
int tidesdb_txn_single_delete(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *key,
                              size_t key_size);

/**
 * tidesdb_txn_commit
 * commit a transaction, writing its batch to the wal and memtable
 * @param txn transaction
 * @return TDB_SUCCESS, TDB_ERR_CONFLICT when another transaction committed a conflicting write
 * first, TDB_ERR_INVALID_ARGS on a NULL or already-finished txn, TDB_ERR_TXN_EXPIRED once a
 * timeout has passed, or TDB_ERR_MEMORY or TDB_ERR_IO
 */
int tidesdb_txn_commit(tidesdb_txn_t *txn);

/**
 * tidesdb_txn_rollback
 * discard a transaction's buffered writes without committing
 * @param txn transaction
 * @return TDB_SUCCESS, or TDB_ERR_INVALID_ARGS on a NULL or already-finished txn
 */
int tidesdb_txn_rollback(tidesdb_txn_t *txn);

/**
 * tidesdb_txn_set_timeout
 * bound how long this transaction may stay active, overriding the database's txn_timeout_seconds
 * for this one. the deadline is measured from the moment of this call, so calling it again on a
 * live transaction extends it. an abandoned transaction holds its snapshot and its write
 * reservations, which keeps the reclamation floor down and stops compaction dropping old versions,
 * so bounding one that may be left unresolved is what stops it costing space indefinitely.
 *
 * the transaction is not aborted in the background when the deadline passes -- the next operation
 * on it notices, aborts it, and returns TDB_ERR_TXN_EXPIRED.
 * @param txn transaction
 * @param seconds seconds from now at which it expires, or <= 0 to clear any timeout
 * @return TDB_SUCCESS, or TDB_ERR_INVALID_ARGS for a NULL or already-resolved transaction
 */
int tidesdb_txn_set_timeout(tidesdb_txn_t *txn, int64_t seconds);

/**
 * tidesdb_txn_request_abort
 * abort a transaction that another thread is running, so its next operation fails rather than
 * whatever it would otherwise have done. this is the one call in the API that may be made on a
 * transaction owned by a different thread.
 *
 * it exists for a caller that is itself the authority on whether a transaction may proceed -- a
 * replication plugin whose cluster has certified against this one, say. the engine's own
 * first-committer-wins verdict decides between two transactions racing on the same key, but it
 * cannot know that something outside has already ruled, so the ruling has to be able to come in
 * from outside.
 *
 * the call stores a flag and does nothing else: the transaction is not rolled back here, and no
 * state is changed on this thread. the thread running the transaction observes the flag when it
 * next enters an operation, aborts it there, and returns TDB_ERR_TXN_ABORTED -- a code of its own
 * so a caller can tell an outside ruling from the engine's own TDB_ERR_CONFLICT. that thread then
 * frees the transaction as it normally would.
 *
 * a request that lands just after the running thread has checked lets the operation in progress
 * finish and stops the one after it. a caller needing the abort to take effect before a particular
 * operation must not be racing that operation, and is expected to hold the transaction still by its
 * own means, exactly as it would to abort a transaction anywhere else.
 *
 * a transaction that has already prepared is not affected: it has voted, and only the coordinator's
 * decision may resolve it, so tidesdb_txn_commit_prepared and tidesdb_txn_rollback_prepared proceed
 * regardless. abort before the prepare, or abandon it through the coordinator afterwards
 * @param txn the transaction to abort; NULL is a no-op, as is an already-resolved transaction
 */
void tidesdb_txn_request_abort(tidesdb_txn_t *txn);

/* ===== two-phase commit (2pc / xa) ===== */

/**
 * tidesdb_txn_prepare
 * two-phase-commit phase one -- run the same conflict checks as commit and durably log the write
 * batch under the given transaction id, but leave the writes invisible and unapplied so a
 * coordinator can gather votes from every participant before deciding. on success the transaction
 * moves to the prepared state and holds its snapshot and reservations until resolved with
 * tidesdb_txn_commit_prepared or tidesdb_txn_rollback_prepared. a read-only transaction prepares
 * with nothing durable and needs no phase two. the xid is copied
 * @param txn transaction
 * @param xid the transaction id to record durably
 * @param xid_size length of xid in bytes, must be greater than zero
 * @return TDB_SUCCESS, TDB_ERR_CONFLICT, TDB_ERR_INVALID_ARGS, TDB_ERR_TXN_EXPIRED,
 *         TDB_ERR_MEMORY or TDB_ERR_IO
 */
int tidesdb_txn_prepare(tidesdb_txn_t *txn, const uint8_t *xid, size_t xid_size);

/**
 * tidesdb_txn_commit_prepared
 * two-phase-commit phase two -- durably log the decision to commit the prepared transaction, then
 * apply its batch and make it visible. valid only on a prepared transaction. a transient io failure
 * leaves it prepared so the coordinator can retry
 * @param txn a prepared transaction
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS if the transaction is not prepared, or TDB_ERR_MEMORY
 * or TDB_ERR_IO
 */
int tidesdb_txn_commit_prepared(tidesdb_txn_t *txn);

/**
 * tidesdb_txn_rollback_prepared
 * two-phase-commit phase two -- durably log the decision to roll back the prepared transaction and
 * release its reservations. nothing was applied, so nothing is undone. valid only on a prepared
 * transaction; a transient io failure leaves it prepared so the coordinator can retry
 * @param txn a prepared transaction
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS if the transaction is not prepared, or TDB_ERR_MEMORY
 * or TDB_ERR_IO
 */
int tidesdb_txn_rollback_prepared(tidesdb_txn_t *txn);

/**
 * tidesdb_prepared_txn_t
 * one transaction that was durably prepared before a restart and has no decision recorded after it
 * @field txn a handle in the prepared state, resolved with tidesdb_txn_commit_prepared or
 *            tidesdb_txn_rollback_prepared and freed like any other transaction
 * @field xid the transaction id the coordinator prepared it under, borrowed from the database and
 *            valid until it is closed
 * @field xid_size length of xid in bytes
 */
typedef struct
{
    tidesdb_txn_t *txn;
    const uint8_t *xid;
    size_t xid_size;
} tidesdb_prepared_txn_t;

/**
 * tidesdb_recover_prepared
 * list the transactions that were durably prepared before the last shutdown and never committed or
 * rolled back, so a coordinator can finish deciding them. one that was decided in the log is
 * settled during open and never appears here. the set is fixed when the database opens, so a caller
 * may size its buffer with a first call passing max 0 and then fill it with a second
 * @param db database handle
 * @param out receives the in-doubt transactions, or NULL to only count them
 * @param max capacity of out in entries, ignored when out is NULL
 * @param out_count receives how many in-doubt transactions there are, set even when out is too
 *                  small to hold them
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_TOO_LARGE when out is given and max is below
 *         out_count, in which case nothing was written and no handle was created, or TDB_ERR_MEMORY
 */
int tidesdb_recover_prepared(tidesdb_t *db, tidesdb_prepared_txn_t *out, int max, int *out_count);

/**
 * tidesdb_txn_state
 * report a transaction's lifecycle state so a coordinator can tell a prepared transaction from a
 * resolved one
 * @param txn transaction
 * @param out_state receives the state
 * @return TDB_SUCCESS or TDB_ERR_INVALID_ARGS
 */
int tidesdb_txn_state(const tidesdb_txn_t *txn, tidesdb_txn_state_t *out_state);

/**
 * tidesdb_txn_reset
 * reset a transaction for reuse at a new isolation level, discarding its buffered state
 * @param txn transaction
 * @param isolation isolation level for the reset transaction
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS on a NULL txn, or TDB_ERR_MEMORY
 */
int tidesdb_txn_reset(tidesdb_txn_t *txn, tidesdb_isolation_level_t isolation);

/**
 * tidesdb_txn_free
 * free a transaction handle, rolling it back if still open
 * @param txn transaction, may be NULL
 */
void tidesdb_txn_free(tidesdb_txn_t *txn);

/* ===== savepoints ===== */

/**
 * tidesdb_txn_savepoint
 * mark a named savepoint in a transaction to roll back to later
 * @param txn transaction
 * @param name savepoint name
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS on a NULL txn or name, TDB_ERR_TXN_EXPIRED once a
 * timeout has passed, or TDB_ERR_MEMORY
 */
int tidesdb_txn_savepoint(tidesdb_txn_t *txn, const char *name);

/**
 * tidesdb_txn_rollback_to_savepoint
 * discard writes buffered since a named savepoint
 * @param txn transaction
 * @param name savepoint name
 * @return TDB_SUCCESS, TDB_ERR_NOT_FOUND when no savepoint carries that name,
 * TDB_ERR_INVALID_ARGS on a NULL txn or name, or TDB_ERR_TXN_EXPIRED once a timeout has passed
 */
int tidesdb_txn_rollback_to_savepoint(tidesdb_txn_t *txn, const char *name);

/**
 * tidesdb_txn_release_savepoint
 * release a named savepoint without rolling back
 * @param txn transaction
 * @param name savepoint name
 * @return TDB_SUCCESS, TDB_ERR_NOT_FOUND when no savepoint carries that name,
 * TDB_ERR_INVALID_ARGS on a NULL txn or name, or TDB_ERR_TXN_EXPIRED once a timeout has passed
 */
int tidesdb_txn_release_savepoint(tidesdb_txn_t *txn, const char *name);

/* ===== iterators =====
 *
 * a scan reaches the same sstables a point read does, so every call here can report TDB_ERR_LOCKED
 * for the same reason and with the same remedy -- the position did not move, nothing is wrong with
 * the iterator, and the step should be retried. it is not the end of the range; that is what
 * tidesdb_iter_valid reports. */

/**
 * tidesdb_iter_new
 * create an iterator over a column family at the transaction snapshot
 * @param txn transaction providing the read snapshot
 * @param cf column family to iterate
 * @param iter out -- the new iterator
 * @return TDB_SUCCESS, TDB_ERR_LOCKED when the descriptor budget or a moving source set left the
 *         scan unopenable and the call should be retried, TDB_ERR_INVALID_ARGS on a NULL txn, cf
 *         or iter, or TDB_ERR_MEMORY, TDB_ERR_IO or TDB_ERR_CORRUPTION from a source read
 */
int tidesdb_iter_new(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, tidesdb_iter_t **iter);

/**
 * tidesdb_iter_new_range
 * create an iterator over the part of a column family a scan will actually read, at the transaction
 * snapshot
 *
 * an iterator holds one open cursor per sstable that could answer it, descends each of them on
 * every seek and compares each of them on every step. telling it the range up front lets it leave
 * out the sstables whose own key range cannot meet it, so a scan of a narrow band costs what that
 * band costs rather than what the whole column family costs. on a family holding hundreds of
 * sstables that is the difference between a scan that competes for the whole store and one that
 * does not, which is what makes concurrent range scans scale
 *
 * the range is a promise about what will be read, not a fence the iterator enforces. results are
 * defined only inside it, because the sstables that could answer outside it were never opened --
 * seeking or stepping past either end may report absent a key that exists. use
 * tidesdb_iter_new for a scan whose extent is not known in advance
 * @param txn transaction providing the read snapshot
 * @param cf column family to iterate
 * @param lower range start, inclusive
 * @param lower_size size of lower in bytes
 * @param upper range end, inclusive for the purpose of choosing sstables, so an exclusive end may
 *              be passed unchanged and at worst keeps one sstable the scan never reads from
 * @param upper_size size of upper in bytes
 * @param iter out -- the new iterator
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS when either end is missing, TDB_ERR_LOCKED when the
 *         descriptor budget or a moving source set left the scan unopenable and the call should be
 *         retried, or TDB_ERR_MEMORY, TDB_ERR_IO or TDB_ERR_CORRUPTION from a source read
 */
int tidesdb_iter_new_range(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *lower,
                           size_t lower_size, const uint8_t *upper, size_t upper_size,
                           tidesdb_iter_t **iter);

/**
 * tidesdb_iter_seek
 * position the iterator at the first key >= the given key
 * @param iter iterator
 * @param key key to seek
 * @param key_size size of key in bytes
 * @return TDB_SUCCESS when the iterator is positioned on an entry, TDB_ERR_NOT_FOUND when the
 * merged stream has none there, TDB_ERR_INVALID_ARGS on a NULL iterator, TDB_ERR_LOCKED when
 * descriptor pressure kept a source from being read, or TDB_ERR_IO, TDB_ERR_CORRUPTION or
 * TDB_ERR_MEMORY from a source read
 */
int tidesdb_iter_seek(tidesdb_iter_t *iter, const uint8_t *key, size_t key_size);

/**
 * tidesdb_iter_seek_for_prev
 * position the iterator at the last key <= the given key
 * @param iter iterator
 * @param key key to seek
 * @param key_size size of key in bytes
 * @return TDB_SUCCESS when the iterator is positioned on an entry, TDB_ERR_NOT_FOUND when the
 * merged stream has none there, TDB_ERR_INVALID_ARGS on a NULL iterator, TDB_ERR_LOCKED when
 * descriptor pressure kept a source from being read, or TDB_ERR_IO, TDB_ERR_CORRUPTION or
 * TDB_ERR_MEMORY from a source read
 */
int tidesdb_iter_seek_for_prev(tidesdb_iter_t *iter, const uint8_t *key, size_t key_size);

/**
 * tidesdb_iter_seek_to_first
 * position the iterator at the first key
 * @param iter iterator
 * @return TDB_SUCCESS when the iterator is positioned on an entry, TDB_ERR_NOT_FOUND when the
 * merged stream has none there, TDB_ERR_INVALID_ARGS on a NULL iterator, TDB_ERR_LOCKED when
 * descriptor pressure kept a source from being read, or TDB_ERR_IO, TDB_ERR_CORRUPTION or
 * TDB_ERR_MEMORY from a source read
 */
int tidesdb_iter_seek_to_first(tidesdb_iter_t *iter);

/**
 * tidesdb_iter_seek_to_last
 * position the iterator at the last key
 * @param iter iterator
 * @return TDB_SUCCESS when the iterator is positioned on an entry, TDB_ERR_NOT_FOUND when the
 * merged stream has none there, TDB_ERR_INVALID_ARGS on a NULL iterator, TDB_ERR_LOCKED when
 * descriptor pressure kept a source from being read, or TDB_ERR_IO, TDB_ERR_CORRUPTION or
 * TDB_ERR_MEMORY from a source read
 */
int tidesdb_iter_seek_to_last(tidesdb_iter_t *iter);

/**
 * tidesdb_iter_next
 * advance the iterator to the next key
 * @param iter iterator
 * @return TDB_SUCCESS when the iterator is positioned on an entry, TDB_ERR_NOT_FOUND when the
 * merged stream has none there, TDB_ERR_INVALID_ARGS on a NULL iterator, TDB_ERR_LOCKED when
 * descriptor pressure kept a source from being read, or TDB_ERR_IO, TDB_ERR_CORRUPTION or
 * TDB_ERR_MEMORY from a source read
 */
int tidesdb_iter_next(tidesdb_iter_t *iter);

/**
 * tidesdb_iter_prev
 * step the iterator to the previous key
 * @param iter iterator
 * @return TDB_SUCCESS when the iterator is positioned on an entry, TDB_ERR_NOT_FOUND when the
 * merged stream has none there, TDB_ERR_INVALID_ARGS on a NULL iterator, TDB_ERR_LOCKED when
 * descriptor pressure kept a source from being read, or TDB_ERR_IO, TDB_ERR_CORRUPTION or
 * TDB_ERR_MEMORY from a source read
 */
int tidesdb_iter_prev(tidesdb_iter_t *iter);

/**
 * tidesdb_iter_valid
 * whether the iterator is positioned on a live key
 * @param iter iterator
 * @return 1 if valid, 0 otherwise
 */
int tidesdb_iter_valid(tidesdb_iter_t *iter);

/**
 * tidesdb_iter_key
 * read the key at the iterator position
 * @param iter iterator
 * @param key out -- newly allocated key the caller frees
 * @param key_size out -- size of key in bytes
 * @return TDB_SUCCESS, TDB_ERR_NOT_FOUND when the iterator is not positioned,
 * TDB_ERR_INVALID_ARGS on a NULL argument, or TDB_ERR_MEMORY. reading a key never touches the
 * value log, so this cannot fail the way tidesdb_iter_value can
 */
int tidesdb_iter_key(tidesdb_iter_t *iter, uint8_t **key, size_t *key_size);

/**
 * tidesdb_iter_value
 * read the value at the iterator position
 * @param iter iterator
 * @param value out -- newly allocated value the caller frees
 * @param value_size out -- size of value in bytes
 * @return TDB_SUCCESS, TDB_ERR_NOT_FOUND when the iterator is not positioned,
 * TDB_ERR_INVALID_ARGS on a NULL argument, TDB_ERR_MEMORY, or TDB_ERR_IO or
 * TDB_ERR_CORRUPTION when resolving a separated value
 */
int tidesdb_iter_value(tidesdb_iter_t *iter, uint8_t **value, size_t *value_size);

/**
 * tidesdb_iter_key_value
 * read the key and value at the iterator position in one call
 * @param iter iterator
 * @param key out -- newly allocated key the caller frees
 * @param key_size out -- size of key in bytes
 * @param value out -- newly allocated value the caller frees
 * @param value_size out -- size of value in bytes
 * @return TDB_SUCCESS, TDB_ERR_NOT_FOUND when the iterator is not positioned,
 * TDB_ERR_INVALID_ARGS on a NULL argument, TDB_ERR_MEMORY, or TDB_ERR_IO or
 * TDB_ERR_CORRUPTION when resolving a separated value
 */
int tidesdb_iter_key_value(tidesdb_iter_t *iter, uint8_t **key, size_t *key_size, uint8_t **value,
                           size_t *value_size);

/**
 * tidesdb_iter_free
 * free an iterator handle
 * @param iter iterator, may be NULL
 */
void tidesdb_iter_free(tidesdb_iter_t *iter);

/* ===== maintenance =====
 *
 * every call here can report TDB_ERR_LOCKED, and it always means the same thing -- the work was not
 * done because something else held what it needed, and asking again later is the remedy. it is
 * never data loss and never a corrupt database.
 *
 * what is held differs. tidesdb_compact and tidesdb_compact_range take one family exclusively and
 * report locked at once if a compaction already holds it, rather than parking the caller behind a
 * merge that can run for minutes -- and in that case the work asked for is usually already under
 * way. tidesdb_backup claims every family the same way, and reports locked if any one of them will
 * not come free. tidesdb_flush_memtable, and tidesdb_checkpoint through it, instead wait a bounded
 * time for the immutable queue to drain and report locked only if it has not, which says flush is
 * not keeping up rather than that anything is wrong with the call. */

/**
 * tidesdb_compact
 * synchronously run one forced compaction pass on a column family, merging even when no trigger is
 * due
 * @param db database handle
 * @param cf column family handle
 * @return TDB_SUCCESS, TDB_ERR_LOCKED if a compaction is already running,
 * TDB_ERR_INVALID_ARGS on a NULL db or cf, or TDB_ERR_MEMORY, TDB_ERR_IO or TDB_ERR_CORRUPTION
 * from a merge
 */
int tidesdb_compact(tidesdb_t *db, tidesdb_column_family_t *cf);

/**
 * tidesdb_compact_range
 * synchronously compact every sstable overlapping [start_key, end_key), merging toward the largest
 * level affected; a NULL endpoint is unbounded, but both NULL is rejected in favor of
 * tidesdb_compact
 * @param db database handle
 * @param cf column family handle
 * @param start_key range start, or NULL for unbounded
 * @param start_key_size size of start_key in bytes
 * @param end_key range end, or NULL for unbounded
 * @param end_key_size size of end_key in bytes
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS on a NULL db, cf or bound, TDB_ERR_LOCKED if a
 * compaction is already running or the layout moved mid-scan, or TDB_ERR_MEMORY, TDB_ERR_IO or
 * TDB_ERR_CORRUPTION from a merge
 */
int tidesdb_compact_range(tidesdb_t *db, tidesdb_column_family_t *cf, const uint8_t *start_key,
                          size_t start_key_size, const uint8_t *end_key, size_t end_key_size);

/**
 * tidesdb_flush_memtable
 * synchronously rotate and flush the memtable to sstables, waiting a bounded time for the
 * immutable queue to drain
 * @param db database handle
 * @return TDB_SUCCESS, TDB_ERR_LOCKED if the queue had not drained when the wait expired, or an
 * error code
 */
int tidesdb_flush_memtable(tidesdb_t *db);

/**
 * tidesdb_is_flushing
 * whether the memtable is currently flushing or rotating
 * @param db database handle
 * @return 1 if flushing, 0 otherwise
 */
int tidesdb_is_flushing(tidesdb_t *db);

/**
 * tidesdb_is_compacting
 * whether a column family has a compaction in progress
 * @param cf column family handle
 * @return 1 if compacting, 0 otherwise
 */
int tidesdb_is_compacting(tidesdb_column_family_t *cf);

/**
 * tidesdb_sync_wal
 * force an fsync of the write-ahead log
 * @param db database handle
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS on a NULL db, or TDB_ERR_IO
 */
int tidesdb_sync_wal(tidesdb_t *db);

/**
 * tidesdb_backup
 * write a consistent, directly-openable copy of the database into dir: flush the memtable, then
 * copy the manifest, the shared value log, and every sstable it references at a single manifest
 * snapshot while compaction is held off, so the copy references no file that a merge could delete
 * mid-copy
 * @param db database handle
 * @param dir destination directory, created if absent
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_LOCKED if a family stayed under compaction
 * for the whole freeze window, TDB_ERR_MEMORY, or TDB_ERR_IO on a copy or io error
 */
int tidesdb_backup(tidesdb_t *db, const char *dir);

/**
 * tidesdb_checkpoint
 * establish a durability barrier in the live database: flush the memtable to L1, then force the
 * value log, the write-ahead log, and the manifest to disk regardless of the configured sync mode
 * @param db database handle
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_LOCKED if the flush it begins with could not
 * drain the immutable queue, or TDB_ERR_IO
 */
int tidesdb_checkpoint(tidesdb_t *db);

/* ===== statistics ===== */

/**
 * tidesdb_get_cf_stats
 * fill a caller-provided column-family statistics struct; a flat value with nothing to free
 * @param cf column family handle
 * @param stats out -- the statistics, filled by this call
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS on a NULL cf or stats, TDB_ERR_LOCKED when descriptor
 * pressure kept a level from being read, or TDB_ERR_MEMORY
 */
int tidesdb_get_cf_stats(tidesdb_column_family_t *cf, tidesdb_cf_stats_t *stats);

/**
 * tidesdb_cf_estimate_cardinality
 * estimate the distinct key count of a column family
 * @param cf column family handle
 * @param out_estimate out -- the estimated distinct key count
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS on a NULL cf or out_estimate, TDB_ERR_LOCKED when
 * descriptor pressure kept a level from being read, or TDB_ERR_MEMORY
 */
int tidesdb_cf_estimate_cardinality(tidesdb_column_family_t *cf, uint64_t *out_estimate);

/**
 * tidesdb_get_db_stats
 * collect database-level statistics
 * @param db database handle
 * @param stats out -- the stats, filled by value
 * @return TDB_SUCCESS, or TDB_ERR_INVALID_ARGS on a NULL db or stats
 */
int tidesdb_get_db_stats(tidesdb_t *db, tidesdb_db_stats_t *stats);

/**
 * tidesdb_get_klog_encoding_stats
 * what each encoding chain achieved on the key logs, one entry per chain the live sstables were
 * written with. a table written before a family changed its codec keeps reporting what its own
 * pipeline achieved, rather than being credited to whatever the family is configured with now
 * @param db database handle
 * @param out receives the entries, caller-allocated
 * @param max capacity of out, at most TDB_MAX_ENCODING_CHAINS is useful
 * @param out_count receives how many were written
 * @return TDB_SUCCESS or TDB_ERR_INVALID_ARGS
 */
int tidesdb_get_klog_encoding_stats(tidesdb_t *db, tidesdb_encoding_stats_t *out, size_t max,
                                    size_t *out_count);

/**
 * tidesdb_get_vlog_encoding_stats
 * what each encoding chain achieved on the separated values, read back from the chain each value
 * records with itself
 * @param db database handle
 * @param out receives the entries, caller-allocated
 * @param max capacity of out, at most TDB_MAX_ENCODING_CHAINS is useful
 * @param out_count receives how many were written
 * @return TDB_SUCCESS or TDB_ERR_INVALID_ARGS
 */
int tidesdb_get_vlog_encoding_stats(tidesdb_t *db, tidesdb_encoding_stats_t *out, size_t max,
                                    size_t *out_count);

/**
 * tidesdb_get_cache_stats
 * collect block-cache statistics
 * @param db database handle
 * @param stats out -- the stats, filled by value
 * @return TDB_SUCCESS, or TDB_ERR_INVALID_ARGS on a NULL db or stats
 */
int tidesdb_get_cache_stats(tidesdb_t *db, tidesdb_cache_stats_t *stats);

/**
 * tidesdb_stall_reason_t
 * the places a caller's own thread can be made to wait inside a write. a commit that took far
 * longer than its peers was held at exactly one of these, and knowing which is the difference
 * between a device that cannot keep up and an engine that is not letting it
 * @TDB_STALL_WAL_APPEND waiting on the write-ahead log -- either for staging-ring space or, under a
 * syncing mode, for the record to reach the file. the two are one figure because both are the same
 * wait on the same single writer, and separating them tells a caller nothing it can act on
 * @TDB_STALL_ROTATE_LOCK waiting to take the rotation lock, so another committer was rotating
 * @TDB_STALL_ROTATE_WORK performing the rotation, which this thread pays on everyone's behalf
 * @TDB_STALL_ADMISSION held by write admission because the unflushed backlog was too deep
 * @TDB_STALL_COUNT the number of reasons, not itself a reason
 */
typedef enum
{
    TDB_STALL_WAL_APPEND = 0,
    TDB_STALL_ROTATE_LOCK,
    TDB_STALL_ROTATE_WORK,
    TDB_STALL_ADMISSION,
    TDB_STALL_COUNT
} tidesdb_stall_reason_t;

/**
 * tidesdb_stall_stat_t
 * how much waiting one reason accounted for since the database opened
 * @count how many times a thread waited here
 * @total_us the summed wait, so a reason's share of all waiting is comparable
 * @max_us the longest single wait, which is what a latency tail is made of
 */
typedef struct
{
    uint64_t count;
    uint64_t total_us;
    uint64_t max_us;
} tidesdb_stall_stat_t;

/**
 * tidesdb_stall_stats_t
 * every wait reason, indexed by tidesdb_stall_reason_t
 * @reasons the per-reason totals
 */
typedef struct
{
    tidesdb_stall_stat_t reasons[TDB_STALL_COUNT];
} tidesdb_stall_stats_t;

/**
 * tidesdb_stall_reason_name
 * a stable short name for a reason, for logging and for a stats table's row label
 * @param reason the reason
 * @return the name, or "unknown" for a value outside the enum
 */
const char *tidesdb_stall_reason_name(tidesdb_stall_reason_t reason);

/**
 * tidesdb_get_stall_stats
 * collect where writers have been made to wait. a write latency tail is answerable from this alone:
 * compare each reason's max against the tail you measured, and its total against the others, rather
 * than attaching a debugger to a stalled commit
 * @param db database handle
 * @param stats out -- the totals, filled by value
 * @return TDB_SUCCESS or TDB_ERR_INVALID_ARGS
 */
int tidesdb_get_stall_stats(tidesdb_t *db, tidesdb_stall_stats_t *stats);

/**
 * tidesdb_io_class_t
 * the kinds of file the engine writes, so device time can be attributed rather than pooled
 * @TDB_IO_SSTABLE key logs, written by flush and compaction
 * @TDB_IO_WAL the write-ahead log, written by its own single flush thread
 * @TDB_IO_VLOG value log segments, written by a commit that separates a value and by the reclaim
 *              that copies live values forward. this is the write cost of key/value separation, so
 *              it is counted apart from the key logs whose size that separation is what keeps down
 * @TDB_IO_COUNT the number of classes, not itself a class
 */
typedef enum
{
    TDB_IO_SSTABLE = 0,
    TDB_IO_WAL,
    TDB_IO_VLOG,
    TDB_IO_COUNT
} tidesdb_io_class_t;

/**
 * tidesdb_io_stat_t
 * what one class asked of the device
 * @ops writes issued
 * @bytes bytes written
 * @total_us the summed time inside those writes
 * @max_us the slowest single write
 */
typedef struct
{
    uint64_t ops;
    uint64_t bytes;
    uint64_t total_us;
    uint64_t max_us;
} tidesdb_io_stat_t;

/**
 * tidesdb_io_stats_t
 * every class, indexed by tidesdb_io_class_t
 * @classes the per-class totals
 */
typedef struct
{
    tidesdb_io_stat_t classes[TDB_IO_COUNT];
} tidesdb_io_stats_t;

/**
 * tidesdb_io_class_name
 * a stable short name for a class, for logging and for a stats table's row label
 * @param cls the class
 * @return the name, or "unknown" for a value outside the enum
 */
const char *tidesdb_io_class_name(tidesdb_io_class_t cls);

/**
 * tidesdb_get_io_stats
 * collect what each class of file asked of the device. this is the other half of
 * tidesdb_get_stall_stats: that says writers waited on the log, this says whether the device was
 * the reason. bytes over total_us is the throughput a class actually achieved -- compare it against
 * what the storage can sustain, because a saturated device and a stalled engine look identical from
 * the application.
 *
 * only handles the engine opens through its descriptor manager are counted, which is every key log
 * and every write-ahead log. the value log and the manifest are not, so this measures the two
 * classes that compete for the device under load rather than every byte the database writes
 * @param db database handle
 * @param stats out -- the totals, filled by value
 * @return TDB_SUCCESS or TDB_ERR_INVALID_ARGS
 */
int tidesdb_get_io_stats(tidesdb_t *db, tidesdb_io_stats_t *stats);

/**
 * tidesdb_range_stats_t
 * what a query planner needs to know about a key range, both figures taken from one layout snapshot
 * so they describe the same instant
 * @field sstables_overlapping sorted runs a scan of the range would merge, the shape of its cost
 * @field estimated_keys live keys the range holds, tombstoned and superseded versions excluded
 * @field keys_exact non-zero when estimated_keys was counted rather than estimated from metadata,
 * so a planner can trust it outright instead of hedging
 */
typedef struct
{
    uint64_t sstables_overlapping;
    uint64_t estimated_keys;
    int keys_exact;
} tidesdb_range_stats_t;

/**
 * tidesdb_range_stats
 * describe the key range [key_a, key_b) for a query planner, reporting both what a scan of it would
 * cost and how many live keys it holds. the count is memtable-aware, so a range whose data has not
 * been flushed yet reports a real cardinality rather than an sstable overlap count, and a key that
 * was flushed and then rewritten counts once. a range small enough to walk is counted exactly and
 * reports keys_exact; a wider one is estimated from sstable metadata without walking, so the call
 * stays cheap enough for plan time whatever the range covers. the estimate takes each sstable's
 * keys in proportion to the share of its own key span the range covers, rather than counting an
 * overlapping file whole -- a file written from a memtable holding interleaved writes spans the
 * entire key space, and counting it whole would report the entire store for a narrow band
 * @param db database handle
 * @param cf column family handle
 * @param key_a range start, inclusive
 * @param key_a_size size of key_a in bytes
 * @param key_b range end, exclusive
 * @param key_b_size size of key_b in bytes
 * @param out out -- the statistics, filled by value
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_LOCKED if the layout moved mid-scan, or
 * TDB_ERR_MEMORY
 */
int tidesdb_range_stats(tidesdb_t *db, tidesdb_column_family_t *cf, const uint8_t *key_a,
                        size_t key_a_size, const uint8_t *key_b, size_t key_b_size,
                        tidesdb_range_stats_t *out);

/**
 * tidesdb_free
 * free a buffer the library allocated and returned to the caller
 * @param ptr buffer to free, may be NULL
 */
void tidesdb_free(void *ptr);

#endif /* __TIDESDB_DB_H__ */
