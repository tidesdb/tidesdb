---
title: Statistics
description: Column family, database, and block cache counters, plus cardinality and range cost estimates.
slug: reference/statistics
part: reference
sidebar:
  order: 6
---

# Statistics

Every statistics call fills a **caller-owned struct by value**. Nothing is allocated and
nothing is freed — declare the struct on the stack, pass its address, and read the fields.

```c
tidesdb_db_stats_t stats;
if (tidesdb_get_db_stats(db, &stats) == TDB_SUCCESS)
    printf("%d sstables\n", stats.total_sstable_count);
/* nothing to free */
```

The values are samples taken without stopping the engine, so counters can be slightly
inconsistent with each other — a flush may land between two fields being read. They are for
monitoring and capacity planning, not for making transactional decisions.

## tidesdb_get_cf_stats

Collect one column family's statistics.

### Synopsis

```c
int tidesdb_get_cf_stats(tidesdb_column_family_t *cf, tidesdb_cf_stats_t *stats);
```

### Description

Fills `stats` with the shape and history of one family. Note the signature takes no database
handle — the family handle is enough.

**Shape of the tree.** `num_levels` is how many levels hold data, and the four
`level_*` arrays are indexed by level up to `TDB_MAX_LEVELS` (8). `read_amp` estimates how
many sstables a point read must consult; it is the number to watch when reads slow down.

| Field | Meaning |
| --- | --- |
| `num_levels` | Levels currently holding data |
| `level_sizes[]` | Bytes per level |
| `level_num_sstables[]` | Sstable count per level |
| `level_key_counts[]` | Keys per level |
| `level_tombstone_counts[]` | Tombstones per level |
| `total_keys` / `total_data_size` | Totals across levels. `total_data_size` is the family's key logs and nothing else, so it equals the sum of `level_sizes`. Values below `value_separation_threshold` are already inside those bytes; what spilled lives in the shared value log, reported at database level as `vlog_file_size` |
| `avg_key_size` / `avg_value_size` | Averages in bytes |
| `read_amp` | Estimated sstables consulted per point read |

**The btree.** `btree_total_nodes`, `btree_max_height`, and `btree_avg_height` describe the
key logs. Height rising over time on a family whose key count is stable usually means the
node size is too small for the keys being stored.

**Tombstones.** `total_tombstones` and `tombstone_ratio` are what the
`tombstone_density_trigger` acts on. A ratio that stays high means deletes are outrunning
compaction. `max_sst_density` and `max_sst_density_level` locate the worst single sstable.

**Write volume.** `wal_bytes_written`, `flush_bytes_written`, `compaction_bytes_written`,
`compaction_bytes_read`, and `user_bytes_written` are cumulative since open.

A family's `wal_bytes_written` is an **attribution**, not a measurement. One log serves the whole
database, so this is the encoded size of this family's own entries; the batch header and the block
framing belong to no single family, and these do not sum to what the log wrote. The database-level
field of the same name is measured at the append and is the one to use.

None of them count a separated value, because the log does not carry one — the record holds an id of
a few bytes and the bytes themselves are in `vlog_bytes_written`. A family whose values are all above
the threshold therefore reports a small `wal_bytes_written` against a large `user_bytes_written`, and
that is the arrangement working rather than an accounting gap.

:::caution[Write amplification has to include the value log]
Compute it as `(wal + flush + compaction_written + vlog_written) / user_bytes_written`, all four from
the **database** statistics.

Leaving `vlog_bytes_written` out is not a rounding error on a store that separates its values, it is
most of the answer. A workload writing 4 KiB values against the default threshold puts nearly every
byte in the value log and almost nothing in the key logs, and the three-term formula reported a write
amplification of **0.11** on a run that had just written eight gigabytes to the log.

What the four-term formula reports on that workload is now close to **1.06**. A separated value goes
to the value log once and the write-ahead log carries only its id, so `wal_bytes_written` collapses
to the records themselves — on one 30 second run, 90 MB of log against 7.9 GB of user data. A store
whose values all stay inline still reports the shape you would expect from one log copy plus one
copy per flush and merge.
:::

**In memory.** `unflushed_key_count` is the distinct keys belonging to this family that are
still only in the memtable. It is the family's share of what a flush would write and what a
crash would have to recover. It is reported as an unsigned figure and floored at zero: the
underlying count can dip below it for an instant when a flush's decrement is observed before the
matching apply increment, and that dip is an artefact of reading two independent updates rather
than a real figure.

**Filter memory.** `filter_resident_bytes` is what this family's partition range filters hold
**outside the block cache**. Each open sstable keeps one routing directory — every partition's
offset and its whole first key — and that directory is ordinary heap memory, not charged against
`block_cache_size`. The filter bit arrays are not counted: those are fetched one partition at a time
per probe and live in the cache, where the configured budget already bounds them.

Two things follow from how it is built. A directory is created on a table's **first probe**, not at
open, so this reads zero for a family nothing has read from yet and climbs as tables are touched.
And its size tracks the number of partitions and the length of the keys, not the volume of data — a
family with long keys and many small tables can hold more here than one storing far more data under
short keys. Summing it across families is what answers "the process is larger than the cache budget
and I want to know why".

**Configuration.** `config` is a copy of the family's current
[configuration](/appendix/configuration), including any runtime changes applied since it was
created. It is filled in here so a caller reading the numbers has the settings that produced
them in the same struct, rather than having to correlate two calls that could disagree.

### Errors

| Code | Cause |
| --- | --- |
| `TDB_ERR_INVALID_ARGS` | `cf` or `stats` is `NULL` |
| `TDB_ERR_LOCKED` | Descriptor pressure kept a level from being read. Transient — retry rather than reporting the family as empty |
| `TDB_ERR_MEMORY` | Allocation failed while collecting the level snapshot |

## tidesdb_cf_estimate_cardinality

Estimate a family's distinct key count.

### Synopsis

```c
int tidesdb_cf_estimate_cardinality(tidesdb_column_family_t *cf, uint64_t *out_estimate);
```

### Description

Estimates how many **distinct** keys the family holds. This is not the same as
`total_keys` from [`tidesdb_get_cf_stats`](#tidesdb_get_cf_stats), which counts entries
across levels and therefore counts a key once per level that holds a version of it.

It is an estimate. Use it for planning, not for anything that must be exact — there is no
exact distinct count short of a full scan.

### Errors

| Code | Cause |
| --- | --- |
| `TDB_ERR_INVALID_ARGS` | `cf` or `out_estimate` is `NULL` |
| `TDB_ERR_LOCKED` | Descriptor pressure kept a level from being read. Transient — retry |
| `TDB_ERR_MEMORY` | Allocation failed while collecting the level snapshot |

## tidesdb_get_db_stats

Collect database-level statistics.

### Synopsis

```c
int tidesdb_get_db_stats(tidesdb_t *db, tidesdb_db_stats_t *stats);
```

### Description

Fills `stats` with figures spanning every family plus the shared write path.

**Inventory.** `num_column_families`, `total_sstable_count`, `total_data_size_bytes`,
`num_open_sstables` (against the `max_open_sstables` budget), and `next_cf_index`.

**Write path pressure.** `immutable_memtable_count` is sealed memtables waiting to be
flushed — the queue that backpressure watches. `compaction_pending_count`, `memtable_bytes`,
and `is_flushing` complete the picture. A persistently non-zero
`immutable_memtable_count` means flush is not keeping up with ingest.

`memtable_bytes` counts every version resident in the write buffer, not one per distinct key, and
counts each by what it occupies rather than by the value it carries. A key overwritten repeatedly
adds a version each time rather than replacing one, because a reader at an older snapshot may still
need the version being superseded. A delete adds one too — a tombstone carries no value but is still
a resident allocation — as does a put of an empty value, which is what a secondary index entry
usually is. It is also the number the rotation threshold reads, so it is the one to watch if a
memtable seems not to be sealing.

**Backpressure.** These four are the ones to alert on:

| Field | Meaning |
| --- | --- |
| `writes_throttled` | Writers made to dwell before being admitted |
| `writes_blocked` | Writers made to wait for the queue to drain |
| `write_stall_us` | Total microseconds writers spent held in admission |
| `write_stall_ceiling_hits` | Writers admitted only because the wait ceiling expired |

All zero means ingest is comfortably within what flush can absorb. `write_stall_ceiling_hits`
climbing is the serious one: it means flush is not draining and writes were let through
anyway to avoid turning a slow database into a stuck one.

Two separate pressures feed these four: the immutable memtable queue, and the write-ahead log's
staging ring. That is worth knowing when reading them, because the two look different — a rising
`write_stall_us` with a flat `writes_blocked` is the ring band doing its job, applying many small
dwells rather than one long stop.

**MVCC.** `global_seq` is the current sequence; `min_snapshot_seq` is the oldest snapshot any
live transaction holds, and it is what gates tombstone reclamation — a long-running
transaction holds it back and keeps garbage alive. `active_txn_count` and
`txn_memory_bytes` cover the live transactions themselves.

**Value log.** `vlog_file_size`, `vlog_value_count` and `vlog_used_bytes` describe the contents;
`vlog_segment_count` is how many files they are spread across, one of which is taking appends.

`vlog_bytes_written` is cumulative rather than a description of the contents, counting every byte
ever appended including the rewrites reclamation performs. It is the term write amplification needs
from the log, and it is the only value-log field that answers what the device was asked to write
rather than what is held now.

`vlog_stored_bytes` is the on-disk length of the indexed values. It is only a meaningful ratio
against `vlog_used_bytes` when the whole store was written under one pipeline — use
[`tidesdb_get_vlog_encoding_stats`](#encoding-stats) instead, which keeps the chains apart.

`vlog_live_bytes` is what the installed sstables still reference, summed from what each records
about the segments its separated values landed in. **It is the figure space amplification is
against.** `vlog_used_bytes` is not: the index names every value whose segment has not been
dropped, reachable or not, so it converges on the file size and reports a store full of garbage as
entirely live.

`vlog_dead_bytes` is the gap between file size and used bytes — space held by values no live key
references, and what a reclaim can recover.

The rest describe reclamation itself, and reset when the handle reopens because they measure what
this process has done rather than what is on disk. `vlog_reclaim_calls` counts every reclaim
attempted; `vlog_reclaim_passes` counts only those that actually drained a segment, and
`vlog_segments_retired` counts the files freed. **Read calls against passes**: a reclaim that is
never called and one that is called and finds nothing to do are different faults with different
fixes, and the passes count alone cannot tell them apart. `vlog_segments_drainable` counts the
sealed segments holding so little live data that emptying them is worthwhile — those are emptied by
the next compaction that carries one of their values, not by the store itself.

**Read `vlog_dead_bytes` against `vlog_segments_drainable`.** The first is the work outstanding and
the second is how much of it is currently actionable. Dead bytes climbing while the drainable count
stays high means compaction is not reaching those segments; dead bytes climbing with nothing
drainable means the garbage is spread thin across segments that are still mostly live.

### Encoding stats {#encoding-stats}

```c
int tidesdb_get_klog_encoding_stats(tidesdb_t *db, tidesdb_encoding_stats_t *out, size_t max,
                                    size_t *out_count);
int tidesdb_get_vlog_encoding_stats(tidesdb_t *db, tidesdb_encoding_stats_t *out, size_t max,
                                    size_t *out_count);
```

`out` is caller-allocated with capacity `max`, and `out_count` receives how many entries were
written; sizing `out` beyond `TDB_MAX_ENCODING_CHAINS` gains nothing, since that is the most that
can exist. Both return `TDB_SUCCESS`, or `TDB_ERR_INVALID_ARGS` on a `NULL` argument.

`tidesdb_get_klog_encoding_stats` and `tidesdb_get_vlog_encoding_stats` report one row per encoding
chain, up to `TDB_MAX_ENCODING_CHAINS`. Each row names the chain in `ids` (the codec ids in the order
applied, with `id_count` of them, and empty when the data was stored verbatim) and then reports
`logical_bytes`, `stored_bytes`, and `item_count` — values for the value log, sstables for the key
logs. **`logical_bytes / stored_bytes` is that codec's realised ratio on the data it actually
wrote.**

They are reported per chain rather than per column family for a reason. A family can change its
codec, and compaction rewrites data under whichever pipeline is merging it, so a single figure for a
family averages across settings that no longer apply. A key log is attributed by the pipeline
recorded in its own footer; a value is attributed by the chain recorded in its own block header. A
family mid-migration shows two rows, which is the truth, rather than one number that is not.

**Durability.** `wal_generation` is the current write-ahead log generation, incremented on
each rotation. `flush_count` and `compaction_count` are cumulative, alongside the same
byte counters as the per-family stats.

### Errors

`TDB_ERR_INVALID_ARGS` if `db` or `stats` is `NULL`.

## tidesdb_get_stall_stats

Report where writers have been made to wait.

### Synopsis

```c
int tidesdb_get_stall_stats(tidesdb_t *db, tidesdb_stall_stats_t *stats);
const char *tidesdb_stall_reason_name(tidesdb_stall_reason_t reason);
```

### Description

A write latency tail is one of the hardest things to explain from the outside: the p50 is fine, a
handful of commits take a thousand times longer, and nothing in the ordinary statistics says which
part of the engine held them. This answers that directly. Every place a caller's own thread can be
made to wait reports a **count**, a **total**, and the **longest single wait** — and it is the last
one that a tail is made of, since a total cannot tell many short waits from one long one.

| Reason | Constant | The caller was |
| --- | --- | --- |
| `wal_append` | `TDB_STALL_WAL_APPEND` | waiting on the write-ahead log — for staging-ring space, or under a syncing mode for its record to reach the file |
| `rotate_lock` | `TDB_STALL_ROTATE_LOCK` | taking the rotation lock, which a committer declines rather than waits for when another thread holds it |
| `rotate_work` | `TDB_STALL_ROTATE_WORK` | performing the rotation itself, which one committer pays on every other's behalf |
| `admission` | `TDB_STALL_ADMISSION` | held by write admission because the unflushed backlog was too deep |
| `manifest_commit` | `TDB_STALL_MANIFEST_COMMIT` | inside a manifest commit, which every flush install, every compaction install and every DDL serialises through |

The short name is what `tidesdb_stall_reason_name` returns; the constant is how you index
`reasons[]` for one particular reason. `TDB_STALL_COUNT` is the number of reasons, not itself a
reason.

Read it by comparing each reason's `max_us` against the tail you measured. If one of them matches
the tail, that is where the time went. If `wal_append` dominates, the log is the constraint and the
next question is whether the device can keep up — compare the bytes written against what the device
can sustain, because a saturated disk and a stalled engine look identical from the application.

`manifest_commit` is the one to read against the durability mode. Under `TDB_SYNC_NONE` a commit is
bookkeeping only and costs a couple of microseconds, so a non-trivial total there means something
else. Under a syncing mode it carries an fsync, and periodically a rollover that rewrites the whole
catalogue — both under an exclusive lock every installer needs — so a total that grows with the
flush rate is that serialisation rather than a fault.

A reason reporting a non-zero total against a zero longest is an accounting fault, not a reading:
every path that adds to a total must also offer its wait to the maximum.

The totals are cumulative since the database opened and never reset, so sample twice and subtract to
attribute a particular window.

### Return Value

`TDB_SUCCESS`, or `TDB_ERR_INVALID_ARGS` if `db` or `stats` is `NULL`.
`tidesdb_stall_reason_name` returns a stable short name, or `"unknown"` outside the enum.

### Thread Safety

Safe from any thread at any time. The counters are relaxed atomics on the write path — they are
reported, never decided on — so reading them neither blocks writers nor perturbs what it measures.

The longest is the one exception, and it is there for the comparison above. It is published and read
with enough ordering that `total_us` is always at least `max_us`; without it the two could be seen
in either order, and a reason whose total is still small would report a longest wait larger than the
sum containing it. The same holds for the per-class write statistics below.

### Examples

```c
tidesdb_stall_stats_t stalls;
if (tidesdb_get_stall_stats(db, &stalls) == TDB_SUCCESS)
    for (int i = 0; i < TDB_STALL_COUNT; i++)
        printf("%-12s count=%llu total_ms=%.1f max_ms=%.1f\n",
               tidesdb_stall_reason_name((tidesdb_stall_reason_t)i),
               (unsigned long long)stalls.reasons[i].count,
               (double)stalls.reasons[i].total_us / 1000.0,
               (double)stalls.reasons[i].max_us / 1000.0);
```

### See Also

[`tidesdb_get_db_stats`](#tidesdb_get_db_stats)

## tidesdb_get_io_stats

Report what each class of file asked of the device.

### Synopsis

```c
int tidesdb_get_io_stats(tidesdb_t *db, tidesdb_io_stats_t *stats);
const char *tidesdb_io_class_name(tidesdb_io_class_t cls);
```

### Description

This is the other half of
[`tidesdb_get_stall_stats`](#tidesdb_get_stall_stats). That one says writers waited on the log;
this one says whether the device was the reason, and how much traffic the rest of the engine was
putting beside it.

| Class | Constant | Written by |
| --- | --- | --- |
| `sstable` | `TDB_IO_SSTABLE` | flush and compaction, writing key logs |
| `wal` | `TDB_IO_WAL` | the write-ahead log's own single flush thread |
| `vlog` | `TDB_IO_VLOG` | value log segments, written by a commit that separates a value and by the reclaim that copies live values forward |

As with the stall reasons, the short name is what `tidesdb_io_class_name` returns and the constant
is how you index `classes[]`; `TDB_IO_COUNT` is the number of classes, not itself a class.

Each class reports `ops` writes issued, `bytes` written, `total_us` summed inside those writes, and
`max_us` for the slowest single one.

Read `bytes` over `total_us` as the throughput that class achieved, and `bytes` over `ops` as the
average write size — a class issuing many small writes pays per-call overhead that the throughput
figure alone hides. The comparison that matters is between the two classes: if `sstable` is moving
several times the bytes the `wal` is, the log's writes are queued behind that traffic, and the lever
is **write amplification** rather than anything in the log.

:::caution[What the timings measure]
These time the write call, not the platter. Under `TDB_SYNC_NONE` a write returns once it reaches
the page cache, so the reported rates can far exceed what the storage can sustain and the device
catches up afterwards. Under `TDB_SYNC_FULL` they are device time. In either mode compare the
**bytes** between classes — that ratio is real — and cross-check absolute throughput against a `dd`
control on the same filesystem.
:::

Only handles opened through the engine's descriptor manager are counted, which is every key log and
every write-ahead log. The value log and the manifest are not, so this measures the two classes that
compete for the device under load rather than every byte the database writes.

Totals are cumulative since open and never reset, so sample twice and subtract for a window.

### Return Value

`TDB_SUCCESS`, or `TDB_ERR_INVALID_ARGS` if `db` or `stats` is `NULL`.
`tidesdb_io_class_name` returns a stable short name, or `"unknown"` outside the enum.

### Thread Safety

Safe from any thread at any time; the counters are relaxed atomics on the write path, apart from
`max_us`, which carries enough ordering that `total_us` is always at least as large as it.

### See Also

[`tidesdb_get_stall_stats`](#tidesdb_get_stall_stats),
[`tidesdb_get_db_stats`](#tidesdb_get_db_stats)

## tidesdb_get_cache_stats

Collect block cache statistics.

### Synopsis

```c
int tidesdb_get_cache_stats(tidesdb_t *db, tidesdb_cache_stats_t *stats);
```

### Description

Fills `stats` for the database-wide block cache, which every column family shares.

| Field | Meaning |
| --- | --- |
| `enabled` | 1 when a cache is configured |
| `total_entries` / `total_bytes` | Current residency |
| `hits` / `misses` | Cumulative since open |
| `hit_rate` | `hits / (hits + misses)`, 0 when neither has happened |
| `num_partitions` | Shards, derived from the configured size and the CPU count |

`hit_rate` is the number that matters. A low rate on a read-heavy workload usually means
`block_cache_size` is too small for the working set. Because it is cumulative since open, it
is slow to reflect a recent change — compare deltas between two samples rather than the
absolute value.

### Errors

`TDB_ERR_INVALID_ARGS` if `db` or `stats` is `NULL`.

## tidesdb_range_stats

Describe a key range for a query planner.

### Synopsis

```c no-compile
typedef struct
{
    uint64_t sstables_overlapping;
    uint64_t estimated_keys;
    int keys_exact;
} tidesdb_range_stats_t;
```

```c
int tidesdb_range_stats(tidesdb_t *db, tidesdb_column_family_t *cf, const uint8_t *key_a,
                        size_t key_a_size, const uint8_t *key_b, size_t key_b_size,
                        tidesdb_range_stats_t *out);
```

### Description

Answers the two questions a planner asks about `[key_a, key_b)` — what a scan of it would cost,
and how many rows it would return. Both come from **one layout snapshot**, so they describe the
same instant rather than two moments the caller cannot distinguish.

`sstables_overlapping` is the number of sorted runs a scan would merge. That is the shape of the
scan's cost, and it is what decides between a range scan and a series of point lookups.

`estimated_keys` is the live key count. It is **memtable-aware**: a range whose data has not been
flushed yet reports a real cardinality rather than zero, and a key that was flushed and then
rewritten counts once rather than twice. Tombstoned keys are excluded, so a heavily deleted range
reports what a reader would actually see.

`keys_exact` is what makes the count usable. A range small enough to walk is **counted**, and this
flag is set. A wider one is estimated from sstable metadata without walking, and the flag is clear.
A planner can commit to an exact figure and hedge on an estimated one — which it cannot do if both
arrive as the same opaque number.

The gating is what keeps the call cheap at plan time. The metadata pass runs first and decides
whether walking is worth it, so a wide range costs no more than the overlap count alone, and the
walk only happens when it is provably short.

The estimate takes each overlapping sstable's keys **in proportion to the share of its own key span
the range covers**, interpolating both against the bounds the file records. Counting an overlapping
file whole would be badly wrong in the shape that matters most: a file flushed from a memtable that
held interleaved writes spans the entire key space, so every narrow range meets it, and every narrow
range would be told it holds the entire store. That error compounds — an inflated estimate also
pushes the range past the threshold under which it would have been counted exactly, so the caller
loses the precise answer as well as getting a wrong approximate one.

Interpolation assumes keys are spread evenly within a file, which is rough for skewed key
distributions. It is calibrated for being in the right order of magnitude rather than being exact,
and the narrow ranges where precision matters most are the ones that fall under the threshold and
get counted.

### Errors

`TDB_ERR_INVALID_ARGS` if `db`, `cf`, either key, or `out` is `NULL`. Note that unlike the range
functions elsewhere in the API, **neither key may be `NULL`** — there is no unbounded form.

`TDB_ERR_LOCKED` if the level layout changed while it was being read; the call is safe to retry.

`TDB_ERR_MEMORY` if the working set of sstable entries could not be allocated.

