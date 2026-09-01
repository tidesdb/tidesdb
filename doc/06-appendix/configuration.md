---
title: Configuration Reference
description: Every configuration field, its default, and what changing it does.
slug: appendix/configuration
part: appendix
sidebar:
  order: 3
---

# Configuration Reference

Two structures. Both are filled by a `tidesdb_default_*` call and adjusted; both are borrowed
by the call that takes them and may be freed immediately after.

## Database configuration

`tidesdb_config_t`, from `tidesdb_default_config()`.

| Field | Default | Effect |
| --- | --- | --- |
| `db_path` | none | The database directory. **Must be set.** |
| `num_flush_threads` | 2 | Workers writing sealed memtables to sstables |
| `num_compaction_threads` | 2 | Workers merging sstables |
| `log_level` | `TDB_LOG_INFO` | Engine log verbosity |
| `log_to_file` | 0 | Write the log to `LOG` in the database directory rather than stderr |
| `log_truncation_at` | 0 | Truncate that file once it passes this size; 0 never truncates |
| `block_cache_size` | 64 MiB | The database-wide block cache budget |
| `max_open_sstables` | 1024 | Ceiling on resident descriptors for sstable key logs and value-log segments together. The reaper reclaims toward a slightly lower figure — a reserve of an eighth, at least 16 and at most half, is held back so a reader can still open a file while it works, leaving 896 at the default. **Cut at open to fit the process open-file ceiling**, which at the defaults it does not: 1024 against the usual 1024 `ulimit -n` leaves nothing for the manifest, so it comes down to 960 and says so at warn. Raise the ceiling with [`tidesdb_raise_open_file_limit`](/reference/database#tidesdb_raise_open_file_limit) to keep the larger figure. See [the descriptor manager](/internals/fd-manager) |
| `memtable_write_buffer_size` | 64 MiB | Memory the active memtable may occupy before it rotates. A memory budget, not a promise about flush size — see below |
| `memtable_skip_list_max_level` | 12 | Skip list height |
| `memtable_skip_list_probability` | 0.25 | Skip list level probability |
| `memtable_sync_mode` | `TDB_SYNC_NONE` | Durability policy — see [Durability](/concepts/durability) |
| `memtable_sync_interval_us` | 1000000 | Barrier period under `TDB_SYNC_INTERVAL` |
| `value_separation_threshold` | 1024 | Values at or above this size are stored in the shared value log and referenced from the key log. Database level because the value log is one shared structure and the decision keys on the size of a value rather than on which family holds it. A single family can opt out with `keep_values_inline` |
| `vlog_segment_size` | 256 MiB | Size at which the value log seals a segment and opens a fresh one. It does not change the space the store settles at, only what a reclaim costs — smaller segments copy more live data forward, measurably so below the default |
| `memtable_idle_flush_seconds` | 30 | Rotate the active memtable after this long with no write; 0 never does |
| `memtable_l0_queue_stall_threshold` | 16 | Sealed-memtable queue depth at which ingest is paced; writers throttle in a band below it and are held at it, always with a ceiling. It governs **one of three** admission signals — the staging ring and L1 depth pace independently, so raising this may not reduce stalling |
| `txn_timeout_seconds` | 0 (no timeout) | How long a transaction may stay active before the next operation on it expires it. An unresolved transaction holds its snapshot and its reservations, which keeps the reclamation floor down, so bound this if callers may leak transactions. A single transaction overrides it with [`tidesdb_txn_set_timeout`](/reference/transaction#tidesdb_txn_set_timeout) |

:::caution[Zero means "choose for me" in most fields]
`num_flush_threads`, `num_compaction_threads`, `block_cache_size`, `max_open_sstables`,
`value_separation_threshold`, `vlog_segment_size`, `memtable_write_buffer_size`,
`memtable_skip_list_max_level`, and
`memtable_skip_list_probability` are resolved to their defaults by `tidesdb_open` when left at
zero. You cannot request zero flush threads. `memtable_sync_interval_us` is resolved the same way,
but later — the interval-sync ticker substitutes the one-second default when it reads a zero.

The fields where zero is used exactly as given are `log_to_file`, `log_truncation_at`,
`memtable_idle_flush_seconds`, `memtable_l0_queue_stall_threshold`, `txn_timeout_seconds`, and
`memtable_sync_mode`, where zero is the meaningful value `TDB_SYNC_NONE`.
:::

### Log levels

`log_level` is a threshold, not a selection: a message is emitted when its own severity is at least
the configured level, so a higher setting emits strictly fewer lines.

| Level | Value | Emits |
| --- | --- | --- |
| `TDB_LOG_NONE` | 0 | Nothing — logging is off entirely |
| `TDB_LOG_TRACE` | 1 | Everything, including detailed messages meant for debugging the engine |
| `TDB_LOG_INFO` | 2 | Engine status and operations, plus warnings and errors |
| `TDB_LOG_WARN` | 3 | Conditions worth knowing about that are not yet failures, plus errors |
| `TDB_LOG_ERROR` | 4 | Only operations that failed |

`TDB_LOG_NONE` is the one value that is not a threshold — it suppresses every line rather than
admitting those of severity zero and above.

### What to tune first

**`memtable_write_buffer_size`** trades memory for write amplification. Larger means fewer,
bigger flushes and less compaction work, at the cost of memory and a longer recovery replay.

It is a budget on memory occupied, not on data held. An entry costs its key and value plus about
a hundred bytes of skip list node, pointer arrays and version struct. That overhead is fixed per
entry, so it is most of an entry holding a short value and almost none of one holding a large
value. A memtable of 64 byte values reaches a 64 MiB budget holding roughly 28 MB of data; one of
4 KiB values holds very nearly the full 64 MB. If you work with small entries and want the flush
sizes a byte-counting engine would give you, raise this figure accordingly — the memory was always
being used, it simply was not being counted.

**`block_cache_size`** is the main read-performance knob. It also bounds the resident cost of
partition range filters, so a cache too small to hold the working set of filter partitions makes
every point lookup re-read its filter.

Resident memory tracks this figure, but the *number of nodes* it holds is fewer than the budget
divided by the node size: each cached node reserves a whole allocator chunk, and the chunk is twice
the node size a family is created with. Budget for the memory you want resident, and expect a cache
to hold roughly half of it in useful node bytes. A family that raises `btree_klog_block_size` well
above the default gets nodes larger than a chunk, which are allocated to their own size rather than
rounded up. See [the block cache](/internals/block-cache).

**`memtable_sync_mode`** is the durability decision, and the one with the largest performance
consequence.

**`num_flush_threads` and `num_compaction_threads` are not free.** They compete for the same
cores as your application threads; on a saturated machine, raising them takes capacity from the
work generating the data.

`num_compaction_threads` helps a **single** column family as well as several. A merge the planner
could not divide — the tier drain, whose inputs span the key space — splits its key range across
this many threads instead. A database whose write load lands on one hot family is no longer held to
one thread's worth of drain. See [Compaction](/internals/compaction).

## Column family configuration

`tidesdb_column_family_config_t`, from `tidesdb_default_column_family_config()`.

| Field | Default | Effect |
| --- | --- | --- |
| `name` | empty | **Ignored** — the name argument to the create call is authoritative |
| `level_size_ratio` | 10 | Each level holds this many times the one above |
| `min_levels` | 1 | Levels kept before shape triggers apply |
| `dividing_level_offset` | 1 | How far above the largest level the dividing level sits, so 1 means X = L - 2. Selects where a merge writes output partitioned to the largest level's file boundaries |
| `keep_values_inline` | 0 | Hold every value in the key log whatever its size, ignoring the database's `value_separation_threshold` |
| `btree_klog_block_size` | 4096 | Target btree node size |
| `encoding_pipeline` | empty | Encodings applied in order to btree klog nodes and to separated values; see the note below |
| `encoding_count` | 0 | Entries in the pipeline, up to `TDB_ENCODING_PIPELINE_MAX` |
| `enable_bloom_filter` | 1 | Build a partition range filter per sstable |
| `bloom_fpr` | 0.01 | Target false positive rate |
| `default_isolation_level` | `TDB_ISOLATION_READ_COMMITTED` | Level used by `tidesdb_txn_begin_cf` |
| `l1_file_count_trigger` | 4 | L1 file count that triggers compaction |
| `tombstone_density_trigger` | 0.5 | Tombstone fraction that triggers compaction |
| `tombstone_density_min_entries` | 4096 | Entry count below which the density trigger is ignored |
| `commit_hook_fn` | `NULL` | Commit hook registered at create time |
| `commit_hook_ctx` | `NULL` | Context passed to the hook |

### The two that matter most

**`value_separation_threshold`**, which is database level, decides which values are separated.
Below it, values live inline in the btree; at or above it, in the shared value log with a
reference in their place.

Lowering it keeps the btree small and scans fast, and costs a second read on every point lookup
of a separated value. Raising it does the reverse. Match it to your access pattern: scan-heavy
workloads over large values suffer from separation, key-scan workloads benefit from it
enormously. A family whose access pattern differs from the rest of the database can set
`keep_values_inline` and be left out of separation entirely rather than move the threshold every
other family shares.

**`btree_klog_block_size`** interacts with the block manager's 4 KB first-read window. A node
sized just above it costs a second read on every access. 4096 is the default for that reason.
Keep `value_separation_threshold` at or under a quarter of it — an inlined value approaching the
node size leaves a node holding one entry and spends the btree fan-out that makes a lookup cheap.
The pairing is advisory, and a config that breaks it only logs a warning.

## What the encoding pipeline currently does

The field is an array because encodings **stack**: every id is applied in order on write and undone
in reverse on read. The btree is handed the resolved transforms rather than an algorithm id, so it
has no idea what any of them are — which is what makes a custom registered encoding work exactly
like a built-in one.

The ids are resolved to their transforms **once**, when a build starts or an sstable opens, never per
node. The registry is a linear scan, and a node read cannot afford one.

**Klog nodes carry the whole chain.** The footer records the ids, so a reader reconstructs the same
chain from the file rather than from whatever the family happens to be configured with now.

**Separated values carry the whole chain too**, recorded in each value's own block header rather
than taken from the sstable that references it. That is not redundancy: compaction carries a
separated value forward by id without re-reading or re-encoding it, so a value written under one
pipeline can end up referenced by an sstable whose footer records a different one. A value that
described itself by anything other than its own bytes would then be decoded with the wrong chain.
It is also what lets one shared value log hold values from families that encode differently.

An id that names no compression algorithm at all is rejected outright, whether it arrives at create
time or through a runtime update, because the engine would otherwise persist it and then hand it to
a codec dispatch that does not recognise it.

An id that names a real algorithm this build was compiled without is **accepted**, so that a
database written elsewhere still opens. Reading a node written with a codec the build lacks fails at
that read rather than at open.

## Changing configuration at runtime

`tidesdb_cf_update_runtime_config` changes **every** field of a family's configuration while it
is open, optionally persisting it. Existing sstables are not rewritten; new settings apply to
what is written from then on. This is safe because byte-wise key ordering keeps files written
under different settings mergeable.

Database-level configuration is fixed at open.
