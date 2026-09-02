---
title: Operations
description: Backups, checkpoints, forcing compaction and flushes, and what each costs.
slug: administration/operations
part: administration
sidebar:
  order: 2
---

# Operations

TidesDB compacts, flushes, and syncs on its own. Everything here forces work that would
otherwise happen on its own schedule, or establishes a guarantee stronger than the configured
sync mode.

A well-configured database under normal load needs none of it routinely. Reach for these to take
a backup, to make a barrier before something risky, or to move expensive work into a window you
choose rather than one the engine chooses.

## Taking a backup

`tidesdb_backup` writes a consistent, directly-openable copy into a directory you name.

It flushes the memtable, then copies the manifest, the value log, and every sstable the manifest
references — at a single manifest snapshot, with compaction held off, so the copy can never
reference a file a merge deleted mid-copy.

**Write-ahead logs are deliberately not copied.** The flush at the start put every committed write
into the sstables being copied, so a log would add nothing, and a log still being appended to would
copy torn. That is also why the copy has nothing to replay when you open it.

- The database **stays writable** throughout.
- Writes committed during the backup are **not** included; the copy is consistent as of the
  flush at the start.
- Cost and free space needed are proportional to the live on-disk size.

The result is a database directory, not an archive. Restore by pointing `tidesdb_open` at it, or
by copying it into place.

```c
if (tidesdb_backup(db, "/backups/2026-07-30") != TDB_SUCCESS)
{
    /* the copy is incomplete -- do not treat it as a usable backup */
    fprintf(stderr, "backup failed\n");
}
```

Verify a backup by opening it. That exercises the whole recovery path and is the only check that
proves the copy is usable.

## Checkpoints

`tidesdb_checkpoint` flushes the memtable and forces the value log, the write-ahead log, and the
manifest to disk **regardless of sync mode**. When it returns, everything committed beforehand
is on the device.

Use it before anything that could take the machine down: a planned reboot, a storage migration,
a filesystem-level snapshot, a hypervisor operation.

:::caution[Close is not a barrier]
`tidesdb_close` returns `TDB_SUCCESS` for any non-`NULL` handle: the shutdown itself reports
nothing, so an I/O failure while draining cannot reach you through it. Checkpoint first and check
*that* result if you need to know the data landed.
:::

`tidesdb_sync_wal` is the cheaper, narrower version: it forces the log only. It matters most under
`TDB_SYNC_NONE`, where a commit is acknowledged while its record is still staged inside this
process — forcing the log is what carries those commits out to the device. Under
`TDB_SYNC_INTERVAL` it brings the next barrier forward, and under `TDB_SYNC_FULL` it is redundant.

## Forcing compaction

`tidesdb_compact` runs one pass on a family synchronously, merging even when no trigger is due.

It is I/O-heavy in proportion to what it merges and competes with the background pool for the
same device. **Forcing it during peak load makes latency worse, not better.** The legitimate
uses are a known-quiet window, and after a bulk delete.

It fails fast with `TDB_ERR_LOCKED` if the family is already compacting — checking
`tidesdb_is_compacting` first does not prevent that, since a background compaction can start in
between. Handle the error instead.

`tidesdb_compact_range` compacts only the sstables overlapping a key range, which is the right
tool after deleting a contiguous span: a full compaction would do far more work than the space
being reclaimed justifies. Either endpoint may be `NULL` for unbounded, but **both `NULL` is
rejected** rather than silently becoming a full compaction.

## Forcing a flush

`tidesdb_flush_memtable` seals the active memtable and writes it out, returning when done.

Because the memtable is shared, this flushes **every** family — there is no per-family flush.
Writers are not blocked throughout: a fresh memtable is installed immediately and writes
continue into it while the sealed one is written.

Useful before a backup you are taking by other means, or to bound recovery time before a planned
restart.

## Reclaiming space after deletes

Deleting does not immediately free space. A delete writes a tombstone, which shadows older
versions until a merge can prove nothing survives beneath it.

To reclaim promptly after a bulk delete:

1. `tidesdb_flush_memtable` so the tombstones reach L1.
2. `tidesdb_compact_range` over the deleted span, or `tidesdb_compact` for the whole family.

If space still does not fall, check `min_snapshot_seq` against `global_seq` in the database
statistics. A long-running transaction holds the reclamation floor down, and no amount of
compaction will release what it pins.

## Growing the descriptor budget

`max_open_sstables` is **cut at open to fit the process descriptor ceiling**, leaving a fixed
reserve for the manifest, stdio and temporaries. A budget above what the process allows therefore
costs you descriptors you never get rather than `EMFILE` retries, and the cut says so in the log at
warn. This bites at the defaults, not only at the extremes: the default budget is 1024 and the usual
POSIX default `ulimit -n` is also 1024.

So raising the ceiling is what actually buys the descriptors. Raise it first, then set the budget
from what it returns.

```c
long ceiling = tidesdb_raise_open_file_limit(8192);

tidesdb_config_t config = tidesdb_default_config();
config.db_path = "/var/lib/myapp/data";
config.max_open_sstables = (size_t)(ceiling / 2);
```

Raising it after opening does not widen an already-open database's budget.

## Column family operations

**Cloning flushes the whole database memtable**, because it copies files and everything it should
capture has to be in one first. It is heavyweight — proportional to the source family's on-disk
size — and it stalls flushes database-wide while running.

**Renaming does not.** A family's files are named for its immutable id rather than its name, so a
rename moves nothing, drains no flush, and stalls no committer; it is on the order of tens of
microseconds and writes keep landing across it.

Both claim the family against the compaction scheduler so a concurrent DDL or planner pass cannot
act on it mid-update, and both report `TDB_ERR_LOCKED` if the family stays busy with compaction for
the whole quiesce window.

**Dropping destroys data irreversibly** and waits out any in-flight compaction on that family.
Any handle you hold for it is invalid afterwards.
