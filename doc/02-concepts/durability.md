---
title: Durability
description: What "committed" means under each sync mode, what a crash costs, and how to get a stronger guarantee when you need one.
slug: concepts/durability
part: concepts
sidebar:
  order: 3
---

# Durability

When `tidesdb_txn_commit` returns success, something has happened. Exactly *what* is the most
consequential configuration choice you will make, and it is one setting:
`memtable_sync_mode`.

## The three modes

| Mode | On return from commit, the batch is | Survives a process crash | Survives a machine crash |
| --- | --- | --- | --- |
| `TDB_SYNC_NONE` *(default)* | Staged in the log's ring, still in this process | No | No |
| `TDB_SYNC_INTERVAL` | In the operating system's page cache; on the device within the interval | **Yes** | Within the interval |
| `TDB_SYNC_FULL` | On the device | **Yes** | **Yes** |

Read that as a ladder of three questions, each mode answering one more of them. Has the record
left this process? Has it left the operating system? Has it left the device? `TDB_SYNC_NONE`
answers none of them, `TDB_SYNC_INTERVAL` the first, `TDB_SYNC_FULL` all three.

This is the same ladder every mature engine offers under different names.
InnoDB's `innodb_flush_log_at_trx_commit` takes `0`, `2` and `1` for those three rungs, and
Berkeley DB takes `DB_TXN_NOSYNC`, `DB_TXN_WRITE_NOSYNC` and its default. If you have tuned
either, the mapping is exact.

**A clean close loses nothing, in any mode.** Closing the database drains the log's ring and
writes everything staged before the file is closed, so the weakest mode is not a risk you take
on shutdown — only on a crash.

What `TDB_SYNC_NONE` buys is that a commit never waits for a write. That matters more than it
sounds: the log is written by one thread sharing a device with flush and compaction, so when
that device is busy a single write can take hundreds of milliseconds, and under any mode that
waits, every committer inherits that latency. Not waiting removes the coupling outright.

For a great many applications that is the correct trade. A cache, a derived index, an
analytics store, anything reconstructible from an upstream source — losing the last moment of
writes to a crash costs a rebuild, and waiting on every commit costs throughput continuously.

If you need an acknowledged commit to survive your process dying, use `TDB_SYNC_INTERVAL`. It
is the mode that makes that promise, and it does not fsync on the commit path either.

## What `TDB_SYNC_FULL` costs

Commit throughput, because every commit waits for the device rather than returning once the
bytes reach the operating system. How much depends entirely on the storage.

The engine narrows the gap: commits coalesce in the log's staging ring, so concurrent
committers share the cost of one write rather than each paying separately. The more concurrent
your workload, the better `TDB_SYNC_FULL` amortises.

`TDB_SYNC_INTERVAL` is the middle: the log is forced on a timer, so the exposure is bounded by
`memtable_sync_interval_us` rather than being unbounded, without a barrier on every commit.

:::note[Interval mode syncs the log, not the whole database]
Interval mode batches the **write-ahead log**. The durable base — sstables, value log,
manifest — is fsynced under both interval and full modes; only `TDB_SYNC_NONE` skips it. So a
crash under interval risks at most the last interval of *commits*, never the integrity of what
was already flushed.
:::

:::note[A barrier that fails, fails the operation]
Under a syncing mode the fsync is the whole of what durability means, so a barrier that returns an
error is reported rather than absorbed: a catalogue commit whose sync fails is a failed commit, and
the flush or compaction behind it withdraws what it had recorded instead of going on as though the
bytes had landed. Swallowing it would be the worst available outcome — the engine would report the
write durable, and a compaction would go on to unlink the inputs a crash would then need.
:::

:::note[A large value is durable before the record that names it]
A value at or above `value_separation_threshold` goes to the value log during the commit, and the
log record carries only its id. The value is written first, so a crash can leave a value nothing
names — reclaimable garbage — but never a record naming a value that is not there. Under a syncing
mode both are barriered before the commit is acknowledged.
:::

## Stronger guarantees on demand

The sync mode is a standing policy. Two calls give a stronger guarantee at a moment you choose:

**`tidesdb_sync_wal`** forces the log to the device. Every commit acknowledged before it
becomes machine-crash durable. Cheap, and covers the log only.

**`tidesdb_checkpoint`** flushes the memtable and forces the value log, the write-ahead log,
*and* the manifest, regardless of sync mode. When it returns, everything committed beforehand
is on the device. This is the barrier to use before a planned restart, a storage migration, or
a filesystem snapshot.

:::caution[Closing is not a durability barrier]
`tidesdb_close` cannot report a failure — the shutdown path returns no status, so an I/O error
while writing the last of the data is logged, not returned. If you need to know your data
reached the device, call `tidesdb_checkpoint` first and check *its* result.
:::

## What a crash actually costs

Recovery replays the write-ahead logs, so the boundary is *what reached the log*, not what
reached an sstable.

| Situation | Outcome |
| --- | --- |
| Process killed, `TDB_SYNC_FULL` or `TDB_SYNC_INTERVAL` | Nothing acknowledged is lost |
| Process killed, `TDB_SYNC_NONE` | Commits acknowledged but still staged in the ring — this mode acknowledges before the record leaves the process, so a kill takes them with it |
| Machine lost, `TDB_SYNC_FULL` | Nothing acknowledged is lost |
| Machine lost, `TDB_SYNC_INTERVAL` | At most the last interval of commits |
| Machine lost, `TDB_SYNC_NONE` | Commits not yet written out by the OS |
| Crash mid-flush | Nothing; the data is still in the log, and the partial sstable is an orphan the manifest never named |
| Crash mid-compaction | Nothing; inputs remain until their replacement is committed |

The guarantee recovery makes is an **exact prefix**: everything durable is present, and nothing
else is. Not a superset — a torn final record is discarded rather than half-applied. The crash
fuzzer tests precisely this property, and it runs at `TDB_SYNC_FULL`.

Under `TDB_SYNC_FULL` and `TDB_SYNC_INTERVAL`, durable and acknowledged are the same set once a
barrier has passed, so the prefix is the acknowledged one. Under `TDB_SYNC_NONE` they are not:
acknowledgement happens a step earlier, while the record is still staged in this process, so the
prefix recovery restores can stop short of what commit already returned success for.

## Backups

`tidesdb_backup` writes a consistent, directly-openable copy into a directory you name, taken
at a single manifest snapshot with compaction held off, so it can never reference a file a
merge deleted mid-copy. The database stays writable throughout; writes during the backup are
not included.

The result is a database directory, not an archive. Point `tidesdb_open` at it.

## Choosing

Ask what losing the last second of writes costs you.

- **Reconstructible from elsewhere** — `TDB_SYNC_NONE`, with periodic `tidesdb_checkpoint` if
  you want bounded exposure at moments of your choosing.
- **Painful but survivable** — `TDB_SYNC_INTERVAL`, sized to what you can afford to lose.
- **Unacceptable** — `TDB_SYNC_FULL`, and design for concurrency so the coalescing works for
  you.

Whatever you pick, `tidesdb_checkpoint` before anything deliberately risky, and do not read a
successful `tidesdb_close` as evidence your data is safe.
