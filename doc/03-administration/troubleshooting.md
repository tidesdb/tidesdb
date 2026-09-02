---
title: Troubleshooting
description: Symptoms, what causes them, and what to look at.
slug: administration/troubleshooting
part: administration
sidebar:
  order: 4
---

# Troubleshooting

Organised by what you observe rather than by subsystem, because that is what you have when
something is wrong.

## Writes have become slow or are stalling

**Start with** [`tidesdb_get_stall_stats`](/reference/statistics#tidesdb_get_stall_stats). It names
where writers waited, so a tail is attributable without a debugger. Compare each reason's longest
single wait against the tail you measured — whichever matches is where the time went.

If `manifest_commit` dominates, installers are queueing behind the catalogue rather than the data.
Under a syncing mode each commit carries an fsync and periodically a rollover that rewrites the
whole catalogue, both under a lock every flush install, compaction install and DDL needs, so this
grows with the install rate. Under `TDB_SYNC_NONE` a commit is bookkeeping only and should be
microseconds, so a large total there means something is holding that lock rather than the commit
being expensive.

If no reason accounts for the tail you measured, the wait was somewhere the taxonomy does not
cover — the counters name the waits the engine knows how to attribute, not every place a thread can
stop. Allocation, the filesystem, and thread creation are all outside them. That is the point to
capture stacks from the stalled threads rather than to keep reading counters, which is how the two
rotation-lock violations in [invariants](/internals/invariants) were found.

If `wal_append` dominates, compare the two classes in
[`tidesdb_get_io_stats`](/reference/statistics#tidesdb_get_io_stats). When `sstable` is moving
several times the bytes the `wal` is, the log's writes are queued behind flush and compaction, and
the lever is write amplification rather than anything in the log itself.

Then check whether the storage can keep up at all, which is worth answering before touching any
engine setting. A quick control:

```
dd if=/dev/zero of=<db_dir>/ddtest bs=1M count=12288 conv=fdatasync
```

Compare that figure against the engine's own throughput. Consumer SSDs commonly sustain a fraction
of their rated speed once their write cache is exhausted, and a database achieving most of what
`dd` achieves is not the thing to fix. If the device is the limit, the lever is **write
amplification** — `flush_bytes_written` plus `compaction_bytes_written` over `user_bytes_written` —
since halving it halves the traffic competing for the same device.

**Look at** `write_stall_ceiling_hits`, `writes_blocked`, and `immutable_memtable_count` from
`tidesdb_get_db_stats`.

Non-zero stall counters mean ingest is outrunning flush, and writers are being paced
deliberately. The queue depth confirms it.

| Cause | Fix |
| --- | --- |
| Flush cannot keep up | Raise `num_flush_threads`, but only if cores are available |
| Memtable too small, so rotation is constant | Raise `memtable_write_buffer_size` |
| Device saturated by compaction | Lower compaction eagerness, or move compaction to a quiet window |
| Genuinely more write load than the device can take | Nothing configuration can fix |

If the counters are all zero, the write path is not the problem — look at your transaction
pattern instead. Long transactions, or conflicts causing repeated retries, look like slowness
from outside.

## Reads have become slow

**Check the block cache is the size you asked for.** `tidesdb_get_cache_stats` reports
`total_bytes` — compare it against the `block_cache_size` you configured after the cache has had
time to fill. A cache settling well under its budget means something other than the budget is
binding, and the symptom is a miss rate that no amount of extra configured memory improves.

**Look at** cache `hit_rate` and per-family `read_amp`.

A falling hit rate means the working set outgrew `block_cache_size`. Remember the cache also
holds filter partitions, so a cache too small makes every lookup re-read its filter.

Rising `read_amp` means compaction is falling behind for that family, so a lookup consults more
sstables. Check whether `l1_file_count_trigger` is too high, or whether compaction is starved of
threads or device bandwidth.

If a workload reads large separated values, a point-lookup-heavy pattern pays a second read per
value. Raising `value_separation_threshold` keeps values inline at the cost of a larger btree.

## Disk usage will not fall after deleting

**Look at** `min_snapshot_seq` against `global_seq`, then `tombstone_ratio`.

The usual cause is not compaction. It is a **long-running transaction** holding the reclamation
floor down: compaction may not discard anything above `min_snapshot_seq`, so old versions and
tombstones survive no matter how much you compact. A widening gap between the two is the
signature.

A transaction that is never resolved holds that floor forever, and nothing else in the engine can
decide it is safe to let go of.

A **named snapshot** holds it the same way, by design — it is a registered transaction — so one
that is never released is indistinguishable from a leaked one here. Compare
`tidesdb_snapshot_seq` on the snapshots you hold against `min_snapshot_seq`; if one of them matches,
that is what the floor is waiting on, and no timeout will clear it because a snapshot has none.

If your callers can leak one, bound them: set
`txn_timeout_seconds` on the database, or
[`tidesdb_txn_set_timeout`](/reference/transaction#tidesdb_txn_set_timeout) on the transactions
that might be left open. Expiry is lazy, so a bounded transaction is resolved by the next
operation on it rather than by a background sweep.

If the gap is small, the tombstones simply have not been merged deeply enough yet. Flush, then
`tidesdb_compact_range` over the deleted span.

Also check `vlog_file_size` against `vlog_used_bytes` — the gap is value-log space held by values
nothing references.

**If the store is far larger than the data and the `.klog` files are the bulk of it**, check what
the individual files are sized at. A store whose sstables all sit at exactly the same size is
reporting its preallocation extent rather than its data, which points at a build that did not trim
itself. Compare a few file sizes against `total_data_size`; a healthy store has files of varied
sizes well under the 64 MiB extent, and only the builds currently in flight sit at a whole chunk.

**If instead the `.log` files are the bulk of it**, look for a
transaction left prepared. A prepared batch is durable only in the log it was written to, so that
generation's log survives its flush until the batch is decided. Deciding it releases the log. This
is worth checking specifically when TidesDB runs under a coordinator that prepares on every commit —
MariaDB's internal two-phase commit with the binary log enabled does exactly that.

**If none of those explain it, look for orphaned files.** A crash part way through writing an
sstable leaves a `.klog` the manifest never named, and possibly a `.klog.lstmp` beside it. These are
swept at the next open, so a restart reclaims them; a build that fails without the process dying
already cleans up after itself. The sweep is deliberately skipped when the log records a self-healed
manifest, since that catalogue was rebuilt from the files themselves — if you see that warning and
the space does not come back, the leftovers are sstables the rebuild could not read, and they are
worth looking at rather than deleting.

A store written by a version before the sweep existed keeps whatever it accumulated until it is
reopened once.

## `TDB_ERR_LOCKED` appearing in reads

Reads should rarely produce this. Transient contention — a rotating memtable, a momentarily
exhausted descriptor budget — is waited out inside the engine, which wakes the descriptor reaper
and rechecks before giving up. Reaching a caller means the pressure outlasted every recheck, so
treat it as a signal about the system rather than ordinary noise.

Seeing it at all usually means the **descriptor budget** is genuinely exhausted: an sstable read
cannot open its key log even after the reaper has had its chances. Raise the process ceiling with
`tidesdb_raise_open_file_limit` before opening and set `max_open_sstables` accordingly, or reduce
the number of sstables by compacting.

From the maintenance calls it means something else entirely, and is ordinary: another exclusive
operation holds that family. Compact, reconfigure and backup return at once rather than parking you
behind a compaction that may run for minutes. Rename and clone wait first — a bounded quiesce window
of about a minute — and report locked only if the family was held for all of it, so a caller of
those should expect a wait before the answer rather than an immediate one.

:::caution[Never treat it as "not found"]
Code that folds `TDB_ERR_LOCKED` into an absence returns silently wrong answers under load. It
means "ask again", not "not there".
:::

## Commits failing with `TDB_ERR_CONFLICT`

Expected at snapshot and serializable isolation whenever two transactions write the same key.
Retry the whole transaction.

If the rate is high enough to hurt:

- **Are you reading more than you need?** A tracking `tidesdb_txn_get` widens what the commit
  validates. Probes that do not feed a write should use `tidesdb_txn_get_notrack` or
  `tidesdb_txn_contains`.
- **Are transactions too long?** A longer transaction has a wider window to lose a race.
- **Do you need the guarantee?** Append-only workloads are usually correct at
  `TDB_ISOLATION_READ_COMMITTED`, which never conflicts.

## The database will not open

**`TDB_ERR_IO`** — check permissions on the directory, and that it is not on a filesystem
lacking the operations the engine needs.

**`TDB_ERR_CORRUPTION`** — a column family configuration blob did not decode. A damaged manifest
does *not* produce this; it self-heals and logs at warn level.

**It opens but logs a self-heal warning** — the manifest was damaged and was rebuilt from the
sstables. The data is intact. Investigate the storage; check nothing else is writing into the
directory.

## Recovery is slow on open

Recovery replays surviving write-ahead logs. Replay time is proportional to what had not been
flushed when the process stopped.

`memtable_write_buffer_size` is the trade: larger buffers mean less frequent flushing and more to
replay. If recovery time matters more than write throughput, lower it, or checkpoint before
planned restarts.

## Crashes on freeing a returned buffer

The buffer was released with the wrong `free`. Anything TidesDB allocated on your behalf is
released with `tidesdb_free` — the engine may be built against a different allocator, and on
Windows a library and its caller routinely link separate heaps.

Statistics structures are filled by value and must **not** be freed at all.

## Process memory grows while the engine's numbers stay flat

If resident memory climbs steadily but `memtable_bytes`, the block cache figures and
`txn_memory_bytes` are all flat, the growth is in something the engine is holding but not counting.
The engine's memory is meant to be bounded by the write buffer, the cache capacity and live
transactions, so the three of them flat while the process grows is the signal that one of those
bounds is not being enforced rather than that a limit is set too high.

Check `immutable_memtable_count` alongside it. Zero, with writes flowing, means the memtable is not
sealing — the rotation threshold reads `memtable_bytes`, so if that number is not moving the seal
never fires and the write buffer grows past its configured size.

Worth knowing which shape of workload provokes it, because the shape narrows the cause. Writes
spread over distinct keys behave differently from writes concentrated on a few hot keys, since only
the second builds long version chains in the write buffer. Delete-heavy traffic differs again, as a
tombstone occupies a version while carrying no value. So does a workload writing empty or very small
values, which is what secondary index maintenance produces.

A load that stays flat under a uniform key distribution and grows under a skewed one points at
version retention rather than at the volume of data. One that stays flat with large values and grows
with small or absent ones points at something being counted by the bytes a caller supplied rather
than by what the engine allocated to hold it.

## Getting more detail

Raise `log_level` to `TDB_LOG_TRACE` — the most detailed level — and set `log_to_file`, which routes
output to a file named `LOG` inside the database directory instead of stderr. Bound it with
`log_truncation_at` if you leave it on, since a traced engine under load writes steadily. The engine
logs recovery decisions, self-heals, slow rotations, flush and compaction completions, and
backpressure events.

The sink is process-wide, not per-database. If your process opens several, the last one opened with
`log_to_file` owns the file and the others log into it too, until that handle closes.

A rotation the engine considers slow is logged specifically, because it runs on a committing thread
and lands directly in write latency where it is otherwise invisible. The line carries the duration
it measured and a breakdown of where it went — opening the next log, allocating the memtable,
publishing it, handing the sealed one to a flush worker — so the figure to act on is the one in the
log rather than any threshold quoted here.
