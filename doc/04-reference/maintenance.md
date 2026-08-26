---
title: Maintenance Operations
description: Forcing compaction and flushes, durability barriers, backup, and checkpoints.
slug: reference/maintenance
part: reference
sidebar:
  order: 5
---

# Maintenance Operations

TidesDB compacts and flushes on its own. Everything here forces work that would otherwise
happen when a trigger fired, or establishes a durability barrier stronger than the
configured sync mode.

These calls exist for operators and for tests. A well-configured database under normal load
should not need them on a schedule — reach for them to take a backup, to make a barrier
before something risky, or to compact during a known-quiet window rather than letting it
land during a busy one.

## Thread safety

Every call in this chapter is safe from any thread, and the database stays open to readers and
writers while one runs. What they do not do is queue behind each other: each can report
`TDB_ERR_LOCKED`, which always means the work was not done because something else held what it
needed, never that anything was lost or corrupted. Asking again later is the whole remedy.

What is held differs by call. `tidesdb_compact` and `tidesdb_compact_range` take one family
exclusively and report locked immediately if a compaction already holds it, rather than parking
the caller behind a merge that may run for minutes — and in that case the work asked for is
usually already under way. `tidesdb_backup` claims every family the same way and reports locked
if any one of them will not come free. `tidesdb_flush_memtable`, and `tidesdb_checkpoint` through
it, instead wait a bounded time for the immutable queue to drain and report locked only if it has
not, which says flush is not keeping up rather than that anything is wrong with the call.

## tidesdb_compact

Force one compaction pass on a column family.

### Synopsis

```c
int tidesdb_compact(tidesdb_t *db, tidesdb_column_family_t *cf);
```

### Description

Runs one compaction pass synchronously, merging even when no trigger is due. Returns when
the pass is finished.

This is I/O-heavy in proportion to how much data the pass merges, and it competes with the
background compaction pool for the same device. Forcing it during peak load makes latency
worse, not better.

**Fails fast rather than queueing.** If the family is already being compacted — by the
background scheduler or another caller — it returns `TDB_ERR_LOCKED` immediately.

### Errors

| Code | Cause |
| --- | --- |
| `TDB_ERR_INVALID_ARGS` | `db` or `cf` is `NULL` |
| `TDB_ERR_LOCKED` | A compaction is already running on this family |
| `TDB_ERR_IO` / `TDB_ERR_CORRUPTION` | Reading inputs or writing outputs failed |
| `TDB_ERR_MEMORY` | Allocation failed |

### See Also

[`tidesdb_compact_range`](#tidesdb_compact_range),
[`tidesdb_is_compacting`](#tidesdb_is_compacting)

## tidesdb_compact_range

Compact only the sstables overlapping a key range.

### Synopsis

```c
int tidesdb_compact_range(tidesdb_t *db, tidesdb_column_family_t *cf,
                          const uint8_t *start_key, size_t start_key_size,
                          const uint8_t *end_key, size_t end_key_size);
```

### Description

Compacts every sstable overlapping `[start_key, end_key)`, merging toward the largest level
affected. Useful after deleting a contiguous span of keys, where a full compaction would do
far more work than the space being reclaimed justifies.

Either endpoint may be `NULL` for unbounded. **Both `NULL` is rejected** with
`TDB_ERR_INVALID_ARGS` rather than silently becoming a full compaction — use
[`tidesdb_compact`](#tidesdb_compact) when that is what you mean.

The range is half-open: `start_key` is included, `end_key` is not.

### Errors

| Code | Cause |
| --- | --- |
| `TDB_ERR_INVALID_ARGS` | `db` or `cf` is `NULL`, or both endpoints are `NULL` |
| `TDB_ERR_LOCKED` | A compaction is already running on this family |
| `TDB_ERR_IO` / `TDB_ERR_CORRUPTION` | Reading inputs or writing outputs failed |
| `TDB_ERR_MEMORY` | Allocation failed |

## tidesdb_flush_memtable

Rotate and flush the memtable.

### Synopsis

```c
int tidesdb_flush_memtable(tidesdb_t *db);
```

### Description

Seals the active memtable, installs a fresh one, and writes the sealed one out to each
column family's L1, returning when that is done.

The memtable is **shared by every column family**, so this flushes all of them — there is no
per-family flush. This is why
[`tidesdb_rename_column_family`](/reference/column-family#tidesdb_rename_column_family) and
[`tidesdb_clone_column_family`](/reference/column-family#tidesdb_clone_column_family) are
database-wide in their cost.

Writers are not blocked for the whole call: the rotation installs a new active memtable
immediately, and writes continue into it while the sealed one is written out.

The call waits for the **immutable queue to drain**, so on return every generation sealed before it
is in L1 — which is what [backup](#tidesdb_backup) and
[clone](/reference/column-family#tidesdb_clone_column_family) need, since they copy files and
anything still only in memory would be missed.

Under sustained writes from other threads the queue may never be observed empty, and the call then
reports `TDB_ERR_LOCKED` even though this caller's own data has landed. That is deliberate: the
alternative — returning as soon as the caller's own generation lands — lets a copy silently omit
data that was still queued.

:::note[A flush wakes compaction]
Landing sstables in L1 is what the compaction scheduler waits for, so a flush wakes it and the
scheduler claims the families it plans. A [`tidesdb_compact`](#tidesdb_compact) issued straight
after a flush will often find the family claimed and return `TDB_ERR_LOCKED`, which is retryable
contention rather than an error — see [Error codes](/appendix/error-codes). The same applies to
`tidesdb_is_compacting`, which reads the same claim and may be set for planning that has nothing to
do with a merge you requested.
:::

### Errors

| Code | Cause |
| --- | --- |
| `TDB_ERR_INVALID_ARGS` | `db` is `NULL` |
| `TDB_ERR_IO` | Writing an sstable or committing the manifest failed |
| `TDB_ERR_NO_SPACE` | The device is full; the data stays in the memtable and its log until space is freed |
| `TDB_ERR_LOCKED` | The immutable queue did not drain within the wait — either the flush pool is stuck, or writes are arriving faster than it drains |
| `TDB_ERR_MEMORY` | Allocation failed |

### See Also

[`tidesdb_is_flushing`](#tidesdb_is_flushing),
[`tidesdb_checkpoint`](#tidesdb_checkpoint)

## tidesdb_is_flushing

Report whether a flush or rotation is in progress.

### Synopsis

```c
int tidesdb_is_flushing(tidesdb_t *db);
```

### Description

Returns 1 while the memtable is rotating or a sealed memtable is being written out, 0
otherwise. A sample of a moving value — it may be stale the instant it returns, so it is for
monitoring, not for synchronisation. Waiting on it in a loop is a bug.

### Return Value

1 if flushing, 0 otherwise, including for a `NULL` handle.

## tidesdb_is_compacting

Report whether a family is being compacted.

### Synopsis

```c
int tidesdb_is_compacting(tidesdb_column_family_t *cf);
```

### Description

Returns 1 while a compaction is running on `cf`. The same caveat applies: a sample, not a
lock. Checking it before [`tidesdb_compact`](#tidesdb_compact) does not prevent
`TDB_ERR_LOCKED`, since a background compaction can start in between — handle the error
instead.

### Return Value

1 if compacting, 0 otherwise, including for a `NULL` handle.

## tidesdb_sync_wal

Force the write-ahead log to disk.

### Synopsis

```c
int tidesdb_sync_wal(tidesdb_t *db);
```

### Description

Forces an fsync of the write-ahead log, making every commit acknowledged before this call
durable on the device regardless of the configured sync mode.

This is the cheap barrier. Under `TDB_SYNC_NONE` it converts "staged in the log's ring, still
inside this process" into "on the device" for the WAL alone — it waits for the ring to drain
before the fsync, because syncing the descriptor alone would report as durable a record still
held in memory. Under `TDB_SYNC_INTERVAL` it makes the barrier now instead of at the next tick.
Under `TDB_SYNC_FULL` it is redundant, since each commit is already durable when it returns.

It does **not** cover the sstables, the value log, or the manifest. For a barrier across all
of those use [`tidesdb_checkpoint`](#tidesdb_checkpoint).

### Errors

| Code | Cause |
| --- | --- |
| `TDB_ERR_INVALID_ARGS` | `db` is `NULL` |
| `TDB_ERR_IO` | The fsync failed |

## tidesdb_backup

Write a consistent, directly-openable copy of the database.

### Synopsis

```c
int tidesdb_backup(tidesdb_t *db, const char *dir);
```

### Description

Flushes the memtable, then copies the manifest, the shared value log, and every sstable the
manifest references — all at a single manifest snapshot, with compaction held off, so the
copy can never reference a file a merge deleted mid-copy.

The result is a database directory, not an archive. Point
[`tidesdb_open`](/reference/database#tidesdb_open) at it and it opens.

The database stays writable throughout. Writes committed during the backup are not included:
the copy is consistent as of the flush at the start.

Cost and free space required are proportional to the live on-disk size.

### Parameters

| Parameter | Description |
| --- | --- |
| `db` | Database handle |
| `dir` | Destination directory, created if absent. Must not be the live database directory. |

### Errors

| Code | Cause |
| --- | --- |
| `TDB_ERR_INVALID_ARGS` | `db` or `dir` is `NULL` |
| `TDB_ERR_LOCKED` | A column family stayed under compaction for the whole freeze window, so it could not be copied at a consistent point. Retryable |
| `TDB_ERR_MEMORY` | Allocation failed |
| `TDB_ERR_IO` | The directory could not be created, or a file could not be read or written |

### See Also

[`tidesdb_checkpoint`](#tidesdb_checkpoint),
[`tidesdb_clone_column_family`](/reference/column-family#tidesdb_clone_column_family)

## tidesdb_checkpoint

Establish a full durability barrier.

### Synopsis

```c
int tidesdb_checkpoint(tidesdb_t *db);
```

### Description

Flushes the memtable to L1, then forces the value log, the write-ahead log, and the manifest
to disk **regardless of the configured sync mode**. When it returns, everything committed
beforehand is on the device.

This is the strong barrier, and the one to use before anything risky — a host reboot, a
storage migration, a filesystem-level snapshot. It differs from
[`tidesdb_sync_wal`](#tidesdb_sync_wal) in covering the whole durable base rather than the
log alone, and from [`tidesdb_backup`](#tidesdb_backup) in making the live database durable
rather than producing a second copy.

### Errors

| Code | Cause |
| --- | --- |
| `TDB_ERR_INVALID_ARGS` | `db` is `NULL` |
| `TDB_ERR_LOCKED` | The flush it begins with could not drain the immutable queue inside its bounded wait, which says flush is behind rather than that anything is held. Retryable |
| `TDB_ERR_IO` | The flush or one of the fsyncs failed |

### Examples

```c
/* make everything durable before a planned restart */
if (tidesdb_checkpoint(db) != TDB_SUCCESS)
    fprintf(stderr, "checkpoint failed; do not assume the data is on disk\n");

tidesdb_close(db);   /* close cannot report a failure -- see its entry */
```
