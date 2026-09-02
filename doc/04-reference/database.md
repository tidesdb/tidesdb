---
title: Database Operations
description: Opening, closing, configuring, and freeing a TidesDB database handle.
slug: reference/database
part: reference
sidebar:
  order: 1
---

# Database Operations

A TidesDB database is a directory. Opening one recovers everything it contains — the
manifest, the sstables it lists, and any write-ahead logs left behind by the last run —
and starts the background workers. Closing one stops the workers and releases the handle.
Everything else in this manual happens between those two calls.

The handle, `tidesdb_t *`, is opaque and thread-safe. One handle serves every thread in
the process, and a directory is held by **one handle at a time**.

That is enforced rather than left to the caller. Opening takes an exclusive lock file in the
database directory, and a second open — from this process or from another — is refused with
`TDB_ERR_LOCKED` rather than being allowed to corrupt the store. Both axes are covered: the lock
itself keeps other processes out, and a recorded owner pid keeps the same process out, since
`fcntl` locks are per-process and would otherwise let one caller re-lock a directory it already
holds. The lock is released last of all on close, so the directory is available again as soon as
[`tidesdb_close`](#tidesdb_close) returns.

## tidesdb_default_config

Return a database configuration filled with defaults.

### Synopsis

```c
tidesdb_config_t tidesdb_default_config(void);
```

### Description

Returns the configuration by value. There is nothing to free. The intended use is to take
the defaults and adjust the few fields that matter to you, rather than to zero a struct
and fill it in field by field:

```c
tidesdb_config_t config = tidesdb_default_config();
config.db_path = "/var/lib/myapp/data";
config.memtable_sync_mode = TDB_SYNC_FULL;
```

`db_path` has no default and must be set. Every other field is usable as returned.

### Return Value

| Field | Default |
| --- | --- |
| `db_path` | `NULL` — **must be set by the caller** |
| `num_flush_threads` | 2 |
| `num_compaction_threads` | 2 |
| `log_level` | `TDB_LOG_INFO` |
| `block_cache_size` | 64 MiB |
| `max_open_sstables` | 1024 |
| `log_to_file` | 0 (stderr; 1 writes `LOG` inside `db_path`) |
| `log_truncation_at` | 0 (no truncation) |
| `memtable_write_buffer_size` | 64 MiB |
| `memtable_skip_list_max_level` | 12 |
| `memtable_skip_list_probability` | 0.25 |
| `memtable_idle_flush_seconds` | 30 (0 disables idle rotation) |
| `memtable_sync_mode` | `TDB_SYNC_NONE` |
| `memtable_sync_interval_us` | 1000000 (1 second) |
| `memtable_l0_queue_stall_threshold` | 16 |
| `vlog_segment_size` | 256 MiB |
| `txn_timeout_seconds` | 0 (no timeout) |

### Thread Safety

Safe to call from any thread at any time. It reads no shared state.

### See Also

[`tidesdb_open`](#tidesdb_open),
[`tidesdb_default_column_family_config`](/reference/column-family#tidesdb_default_column_family_config)

## tidesdb_open

Open or create a database.

### Synopsis

```c
int tidesdb_open(const tidesdb_config_t *config, tidesdb_t **db);
```

### Description

Opens the database at `config->db_path`, creating the directory if it does not exist. On
an existing database this replays the manifest to rebuild the column family registry and
the level sets, reopens the value log, replays every surviving write-ahead log generation
back into the memtable, and reseeds the sequence clock past everything durable. Prepared
but undecided transactions are recovered into an in-doubt set; see
[`tidesdb_recover_prepared`](/reference/transaction#tidesdb_recover_prepared).

The configuration is **borrowed, not retained**. `tidesdb_open` copies what it needs,
including `db_path`, so the caller may free or reuse the struct as soon as the call
returns.

Fields left at zero are resolved to their defaults rather than being taken literally. This
applies to `num_flush_threads`, `num_compaction_threads`, `block_cache_size`,
`max_open_sstables`, `vlog_segment_size`, `memtable_write_buffer_size`,
`memtable_skip_list_max_level`, and `memtable_skip_list_probability`. A zero in any of those
means "choose for me", so a caller who wants a specific small value must state it — there is no
way to request zero flush threads, for example. Fields not on that list are used exactly as
given, including `memtable_sync_mode`, where zero is the meaningful value `TDB_SYNC_NONE`, and
`memtable_idle_flush_seconds`, where zero disables idle rotation.

A database whose manifest is damaged does not fail to open, and which repair runs depends on the
damage. Corruption **partway through** keeps the readable prefix and rewrites the log as a clean
snapshot. A header that will not validate leaves nothing to keep, so the log is discarded and the
catalogue is **rebuilt from the sstables on disk** — the database directory is scanned and each
`.klog` whose footer reads back is re-registered under the family id its filename carries, which is
what keeps those files reachable rather than orphaned.

A rebuilt family comes back named `cf_` followed by its zero-padded id, with the default
configuration, and its sstables
are placed at L1, because a file records neither its family's name nor the level it sat at. See
[Manifest](/internals/manifest) for the full limits.

Either repair is reported through the log at `TDB_LOG_WARN`, not through the return value.

### Parameters

| Parameter | Description |
| --- | --- |
| `config` | Database configuration, borrowed. `config->db_path` must be non-`NULL` and non-empty. |
| `db` | Out parameter. Receives the handle on success; untouched on failure. |

### Return Value

`TDB_SUCCESS` on success, with `*db` set to a handle the caller closes with
[`tidesdb_close`](#tidesdb_close).

### Errors

| Code | Cause |
| --- | --- |
| `TDB_ERR_INVALID_ARGS` | `config` or `db` is `NULL`, `db_path` is `NULL` or empty, or a path built from `db_path` would not fit the internal path buffer |
| `TDB_ERR_LOCKED` | Another handle already holds this directory — a second open from this process, or an open from another process. Close the first handle, or point at a different directory |
| `TDB_ERR_MEMORY` | Allocation failed while building the handle, the block cache, the arena pool, the memtable, or the worker pools |
| `TDB_ERR_IO` | The database directory could not be created, or the manifest, value log, or a write-ahead log could not be opened |
| `TDB_ERR_CORRUPTION` | A recovered column family configuration blob did not decode |

On any failure the partially built handle is released internally and `*db` is not written,
so the caller has nothing to clean up.

### Thread Safety

Safe to call concurrently for *different* directories. Two concurrent opens of the **same**
directory resolve rather than race: one takes the lock and succeeds, the other is refused with
`TDB_ERR_LOCKED`. That holds whether the second caller is this process or another one, so a
directory is never opened twice and there is no corruption to guard against by convention.

### Notes

`max_open_sstables` is a budget, not a guarantee. Call
[`tidesdb_raise_open_file_limit`](#tidesdb_raise_open_file_limit) **before** opening if you
intend to raise it, because the engine sizes the budget against the ceiling in effect at
open time.

### Examples

```c
tidesdb_config_t config = tidesdb_default_config();
config.db_path = "/var/lib/myapp/data";

tidesdb_t *db = NULL;
int rc = tidesdb_open(&config, &db);
if (rc != TDB_SUCCESS)
{
    fprintf(stderr, "open failed: %d\n", rc);
    return 1;
}
/* ... use db ... */
tidesdb_close(db);
```

### See Also

[`tidesdb_close`](#tidesdb_close),
[`tidesdb_default_config`](#tidesdb_default_config),
[`tidesdb_raise_open_file_limit`](#tidesdb_raise_open_file_limit)

## tidesdb_close

Close a database and release its handle.

### Synopsis

```c
int tidesdb_close(tidesdb_t *db);
```

### Description

Stops accepting new work, drains the flush and compaction pools, writes out what is still
in memory, closes every open file, and frees the handle. After it returns the handle is
invalid and must not be used again.

Closing does not wait for a compaction that would only reduce read amplification; it
finishes what is needed for durability and stops. Data already acknowledged under the
database's sync mode remains durable, and anything still in a write-ahead log is recovered
by the next open.

### Parameters

| Parameter | Description |
| --- | --- |
| `db` | The handle to close. Must not be in use by any other thread. |

### Return Value

`TDB_SUCCESS`, or `TDB_ERR_INVALID_ARGS` if `db` is `NULL`.

**Close cannot report a failure.** It always succeeds for a non-`NULL` handle; the shutdown
path returns no status. An I/O error while writing out the last of the data is logged, not
returned. A caller that needs to know its data reached the device must not rely on the
close return value — use [`tidesdb_sync_wal`](/reference/maintenance#tidesdb_sync_wal) or
[`tidesdb_checkpoint`](/reference/maintenance#tidesdb_checkpoint) beforehand, or run under
`TDB_SYNC_FULL`, where a commit is already durable when it returns.

### Thread Safety

**Not** thread-safe with respect to its own handle. The caller must ensure no other thread
is inside any TidesDB call on this handle, and that every transaction and iterator derived
from it has been freed, before calling.

### See Also

[`tidesdb_open`](#tidesdb_open),
[`tidesdb_checkpoint`](/reference/maintenance#tidesdb_checkpoint)

## tidesdb_raise_open_file_limit

Raise the process's open-file ceiling.

### Synopsis

```c
long tidesdb_raise_open_file_limit(long desired);
```

### Description

Raises this process's descriptor ceiling toward `desired` so that a database can keep more
sstables open at once. This is an explicit operator action: **TidesDB never raises the
limit on its own.**

On POSIX it raises the `RLIMIT_NOFILE` soft limit toward the hard limit, so it can only
reach what the hard limit already permits. On Windows it raises the C runtime's stdio cap,
which tops out at 8192.

A failed or partial raise is not an error. The function reports the ceiling actually in
effect afterwards, which may be lower than `desired` and may be unchanged.

Call it **before** [`tidesdb_open`](#tidesdb_open). The engine sizes `max_open_sstables`
against the ceiling in effect at open time, so raising the limit afterwards does not widen
an already-open database's budget.

### Parameters

| Parameter | Description |
| --- | --- |
| `desired` | Target descriptor count. A value `<= 0` changes nothing and just reports the current ceiling. |

### Return Value

The open-file ceiling in effect after the attempt. Compare it against `desired` to find out
whether the raise was granted in full.

### Thread Safety

Safe to call from any thread, but it changes process-wide state. Call it once during
startup rather than from several threads.

### Examples

```c
long ceiling = tidesdb_raise_open_file_limit(8192);
if (ceiling < 8192)
    fprintf(stderr, "only got %ld descriptors\n", ceiling);

tidesdb_config_t config = tidesdb_default_config();
config.db_path = "/var/lib/myapp/data";
config.max_open_sstables = (size_t)(ceiling / 2);
```

### See Also

[`tidesdb_open`](#tidesdb_open)

## tidesdb_free

Free a buffer the engine allocated.

### Synopsis

```c
void tidesdb_free(void *ptr);
```

### Description

Releases memory handed back by a TidesDB call that allocates on the caller's behalf —
values returned by [`tidesdb_txn_get`](/reference/transaction#tidesdb_txn_get), the name
array from
[`tidesdb_list_column_families`](/reference/column-family#tidesdb_list_column_families),
and so on. Passing `NULL` is safe and does nothing.

Use this rather than `free` from your own C runtime. The engine may be built against a
different allocator — jemalloc, mimalloc, or tcmalloc are all supported build options —
and on Windows a library and its caller routinely link separate C runtime heaps. Freeing an
engine allocation with the wrong `free` is undefined behaviour in both cases.

Statistics structures are **not** freed this way. `tidesdb_get_cf_stats`,
`tidesdb_get_db_stats`, and `tidesdb_get_cache_stats` all fill a caller-owned struct by
value and allocate nothing.

### Parameters

| Parameter | Description |
| --- | --- |
| `ptr` | A pointer returned by a TidesDB call that documents the caller as owning it, or `NULL`. |

### Thread Safety

Safe to call from any thread.

### See Also

[`tidesdb_txn_get`](/reference/transaction#tidesdb_txn_get),
[`tidesdb_list_column_families`](/reference/column-family#tidesdb_list_column_families)
