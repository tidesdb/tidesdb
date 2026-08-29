---
title: The Life of a Write
description: One put followed from the caller's buffer to a merged sstable, through every subsystem it touches.
slug: internals/life-of-a-write
part: internals
sidebar:
  order: 2
---

# The Life of a Write

This chapter follows a single key from `tidesdb_txn_put` to its final resting place in a
compacted sstable. It crosses most of the engine. Nothing here is described in full — each
subsystem has its own chapter — but the order of events is exact, because almost every
durability property falls out of that order.

## Stage 1 — Buffering

`tidesdb_txn_put` copies the key and value into the transaction's write set and returns.
Nothing else happens. The write is invisible to every other transaction and not durable in
any sense.

Copying rather than borrowing is deliberate: a caller may free its buffers the moment the
call returns, and a transaction may live a long time before it commits.

The write set preserves insertion order, which is what makes savepoints work — a savepoint
is a position in that sequence, and rolling back to it discards the tail.

This is also where a transaction that has outlived a timeout finds out. Nothing ages it in the
background; the check happens on the way into an operation, so a stale transaction is aborted here
and this `put` returns `TDB_ERR_TXN_EXPIRED` rather than buffering anything.

## Stage 2 — Commit begins: conflict detection

A read-only transaction stops here: with nothing in the write set there is nothing durable
to do, so it is marked committed and leaves.

For everything else, the isolation level decides what is validated, and the two checks are not
stacked one on top of the other — each level runs the one that suits how it prevents anomalies.

- Below `TDB_ISOLATION_REPEATABLE_READ` there is no check at all; commit proceeds.
- `TDB_ISOLATION_REPEATABLE_READ` and `TDB_ISOLATION_SERIALIZABLE` validate the **read footprint**:
  every key the transaction read is probed for a newer committed version, which is what stops a
  non-repeatable read or a phantom.
- `TDB_ISOLATION_SNAPSHOT` and `TDB_ISOLATION_SERIALIZABLE` scan their **write keys** for a version
  newer than the snapshot — a writer that already applied and so is invisible to the reservation
  taken in stage 4.
- `TDB_ISOLATION_SERIALIZABLE` alone then runs the dangerous-structure check that catches write skew.

A [range delete](/reference/transaction#tidesdb_txn_delete_range) is scanned over its interval
rather than as a key: *does any key in these bounds sit above my snapshot*. Probing its lower bound
as though it were a key would clear a commit about to delete data another transaction had just
written.

:::note[A batch carrying an interval commits alone]
At snapshot and above, a commit that deletes a range takes the database's commit gate exclusively;
every other commit at those levels holds it shared and never waits on another. The gate is held for
the **whole commit**, not just the reservation, because a batch that has reserved but not yet marked
its sequence visible is precisely the write the scan above would otherwise miss.

A two-phase transaction takes it only for its prepare — the in-doubt window that follows has no
bound, and the interval reservation in stage 4 covers that window instead.
:::

Snapshot deliberately does not validate reads: first-committer-wins reservation is how it prevents
lost updates, and validating the read set on top of it would abort transactions the level is
defined to allow.

A conflict aborts here, before anything durable has been written.

## Stage 3 — Sequencing

The transaction draws a commit sequence from the database clock and immediately marks it
**in progress**.

The mark matters. A sequence that has been drawn but not completed must be invisible: a
reader whose snapshot is above it must not see a half-applied batch. Marking it in progress
first, and committed only at the very end, is what makes the batch atomic to readers without
a lock.

## Stage 4 — Reservation

Under snapshot and serializable isolation, every key in the batch is reserved on a
first-committer-wins basis.

The subtlety is what each key is validated *against*. Not the transaction's snapshot, but
**the version this transaction actually read for that key** — recorded when
[`tidesdb_txn_get`](/reference/transaction#tidesdb_txn_get) was called. A blind write with no
prior read falls back to the snapshot. This is why a read-modify-write is checked correctly
while a blind overwrite is not penalised for reading nothing, and it is why
[`tidesdb_txn_get_notrack`](/reference/transaction#tidesdb_txn_get_notrack) exists: a probe
that does not feed the write should not narrow the window the write is validated over.

An interval has no key to hash, so a range delete claims the interval itself in a second, small
table, and every point write checks that table before taking its own slot. The table is almost
always empty, so the check is a single atomic load of its count. The claim is released when the transaction
resolves, which is what carries a two-phase range delete through its in-doubt window.

A lost reservation is `TDB_ERR_CONFLICT`, and still nothing durable has happened.

## Stage 5 — Admission

Before the durable write, the batch is paced once per distinct column family it touches.

This is where a writer waits when the engine is not keeping up. **Three signals feed it, and
the strongest wins** — none is allowed to mask another:

- **The queue of sealed memtables awaiting flush.** As it fills, writers are first made to
  dwell, then held at the limit. This is the one `memtable_l0_queue_stall_threshold`
  configures.
- **The write-ahead log's staging ring.** Its lag is bounded whatever the queue is doing, so
  the ring paces ingest on its own. Its capacity comes from `memtable_write_buffer_size`, not
  from the queue threshold.
- **The depth of overlapping runs in L1.** A tier that has run past its slow mark paces
  writers so compaction can catch up.

The practical consequence is that **raising the queue threshold does not necessarily reduce
stalling**, because the dwell may not be coming from the queue at all. Raising it sixteenfold
on a write-heavy run here changed the total stall not at all; the memtable size did, by a
factor of three, because it sizes the ring and lowers the flush rate at once.

There is a ceiling on the wait — a writer held too long is admitted regardless, because a
flush that never drains would otherwise turn a slow database into a stuck one. Each of those
outcomes is counted, and `write_stall_ceiling_hits` climbing is the serious one.

## Stage 6 — Separating the large values

Before the record is written, every value at or above the database's `value_separation_threshold`
is appended to the [value log](/internals/value-log), and its entry keeps the returned id and the
value's logical length in place of the bytes. A family that set `keep_values_inline` is left out.

**The order is what makes it safe.** It runs after the reservation and the admission wait have both
let this commit through, so a conflict or a refused admission leaves nothing behind in the value
log; and it runs before the record naming the values is appended, so the bytes are on the device
before anything points at them. Under a syncing mode both are barriered before the commit is
acknowledged.

What this buys is that a large value reaches the device **once**. Written inline, it goes into the
log and then again into the sstable the flush builds; written here, the log record carries an id of
a few bytes and the flush carries the same id forward. On a 4 KiB-value workload that is the
difference between a write amplification of 2.10 and 1.06.

A commit that fails after this point leaves its value behind as garbage, which the value log's own
reclamation is what clears.

## Stage 7 — The write-ahead log

The batch is encoded as one self-describing record — a version byte, a kind, an optional
transaction id, then the entries — and appended to the active log.

The append does not write to the file directly. It reserves space in the log's **staging
ring** with a single atomic fetch-and-add, copies its bytes into that reservation, and marks
its slot complete. A dedicated flush thread — the only thread that ever writes this file —
drains the contiguous run of completed records at the frontier and writes it out in one
call. The committer then waits for the frontier to pass its own record.

Three properties come out of this arrangement:

- **Concurrent committers do not serialize.** Space allocation is one atomic; the copy is
  parallel.
- **The log is written in offset order with no gaps.** The flush thread only ever emits the
  *contiguous* completed run, so a record can never be written before one that precedes it.
  This is load-bearing — see below.
- **Durability is the sync mode's business, not the caller's.** Waiting for the frontier
  means the bytes reached the file; whether that means the page cache or the device depends
  on how the file was opened.

:::caution[The log must be gap-free]
Recovery replays the log by reading blocks forward and **stops at the first one it cannot
read**. A hole would not be skipped — everything after it would be silently discarded. The
single-writer-contiguous-run rule is what guarantees no hole exists, and any change to the
append path has to preserve it.
:::

## Stage 8 — Apply

Only now does the batch enter the memtable, at the commit sequence drawn in stage 3.

The order is the point. The log has the batch before memory does, so a crash between the two
recovers it. The reverse order would make the write visible before it was recoverable.

If the apply fails, the batch is already durable, and replay treats a write batch's presence as
its commitment — so left alone the transaction would come back whole on the next open, after its
caller was told it failed. Three things happen instead, in this order:

1. An **abort record** naming the sequence is appended, which is what replay consults to leave
   the batch out.
2. The backend **abandons** the sequence, keeping whatever the failed apply already landed out
   of reads and out of any flush before that next open.
3. The reservations are released and the transaction is marked aborted.

The abort record is best effort by construction: if appending it fails there is nothing further
to try, so the failure is logged rather than returned, and the batch would replay on the next
open. That is the one case where a caller told its transaction failed can still see it applied,
and it is why the failure is logged loudly rather than swallowed.

## Stage 9 — Publication

The sequence is marked committed, and the batch becomes visible to every reader whose
snapshot is at or above it. The transaction leaves the registry, which releases the snapshot
it was holding — and with it, possibly, the floor that was keeping older versions alive.

Any commit hooks registered on the affected families fire here, synchronously, on the
committing thread. Work done in a hook is latency every writer pays.

## Stage 10 — Rotation

The committing thread then checks whether its write filled the memtable. If so it tries to take the
rotation lock, and having it, seals the active memtable, enqueues it, and installs a fresh one. A
thread that finds the lock held does not queue behind it. The rotation is already being done by the
holder, and this thread's write has landed either way, so it returns to its commit.

The order within the rotation is exact: the sealed memtable is **enqueued before** the
active slot is swapped. For a moment it is reachable both ways. The alternative — swap then
enqueue — leaves a window where a reader sees the new active memtable and cannot see the
sealed one, and reads a key that exists as absent.

Rotation does **not** wait for the sealed memtable to be written out, and does not drain its
log's staging ring. The sealed memtable keeps its log alive, which is why a committer waiting
on that log must hold a pin on the memtable across the wait.

## Stage 11 — Flush

A flush worker takes a sealed memtable and demultiplexes it: one shared skip list holding
every family's keys, prefixed by family index, becomes one sstable per family that has data
in it.

The flush walks each key's **version chain** and keeps what the reclamation floor still protects:
every version above it, and the newest at or below it as the base. That is the rule a merge
applies. With nothing registered the floor sits at the top, so the flush writes the newest version
alone and this costs nothing until a reader holds a snapshot under an overwrite. See
[Memtable and WAL](/internals/memtable-and-wal#a-flush-retains-against-the-same-floor-a-merge-does).

Each output is built, then made durable, and only then are they all recorded in the manifest
in **one atomic commit**. That is why the manifest is database-level rather than per-family:
a flush that produced sstables for five families publishes all five or none.

The install that follows the commit can still fail — it allocates, and nothing else about it can
go wrong — so an output that never reaches a level set has its catalogue entry **withdrawn**, and
its file is unlinked only once that withdrawal is itself durable. Unlinking first would leave a
committed catalogue naming a file that is already gone. The memtable is left for a retry either
way, its data still in the log, and the withdrawal is what stops the retry from writing the same
keys a second time beside files nothing will ever read.

Installs are ordered by a ticket. Workers may build in parallel — building is the expensive
part — but each waits its turn to install, so the level sets are mutated in the same order
the memtables were sealed. Out-of-order installs would put an older sstable above a newer one.

That wait happens **before** the worker takes the family registry read lock, not while holding it.
Both the build and the install need that lock, so the families they address cannot be dropped
underneath them — but holding it across the wait as well would stretch one worker's hold to cover
every flush queued ahead of it, and a `create` or `drop` waits behind exactly that. It would also
deadlock outright once writers are preferred, since the worker holding the earlier ticket needs the
same read lock to make progress. The families are therefore re-resolved by id after the wait, and
an output whose family was dropped in the gap is discarded rather than installed.

Once installed, the sealed memtable is reclaimed and its log can be unlinked. Reclamation
needs every reader that had it pinned to leave first, and the flush does not wait for that
indefinitely: it rechecks a bounded number of times, and if a reader is still inside it hands the
memtable to a pending list the reaper sweeps. The flush is holding locks a family create or drop
needs, so a wait there is a wait the whole database feels — see
[Memtable and WAL](/internals/memtable-and-wal#reclaiming-a-sealed-memtable).

## Stage 12 — Compaction

The key now lives in L1, alongside every other key flushed at the same time. From here the
compaction planner decides when it moves down.

The planner is a **pure function**: given a snapshot of level sizes and file counts plus the
family's configuration, it computes the level capacities, the dividing level, the target of
the next merge, the cap on how large a single output file may grow, and whether any trigger
is due. No I/O, no handles, no clock — the same
snapshot always produces the same plan, which is what makes compaction policy testable by
handing it numbers.

Three things make a merge due: L1 accumulating too many files, a level exceeding its
capacity, and tombstone density crossing its threshold.

The merge reads its inputs through the same k-way merge iterator that serves user iterators, but
asks it for a raw stream — every version of every key — and applies its own retention to it. The
newest version survives; older ones are dropped, but only those older than the **oldest live
snapshot**. A long-running transaction holds that floor down and keeps garbage alive; this is
visible as `min_snapshot_seq`.

A tombstone is the hard case. It can only be dropped when the merge can prove no older
version of that key survives beneath it. Drop it too early and the older version is
resurrected. This is why deletes cost space until a merge deep enough to prove it happens,
and why a single-delete — where the caller promises the key was written at most once — can
annihilate immediately.

## The whole path

```
  tidesdb_txn_put         copy into the write set
          |
  tidesdb_txn_commit
          |
     conflict check       snapshot+ only, aborts before anything durable
          |
     draw sequence        marked in progress -> invisible
          |
     reserve keys         first-committer-wins, vs the version actually read
          |
     admission            paced against the flush queue
          |
     separate values      large ones to the value log; the record carries the id
          |               after the reservation, before the record naming them
     WAL append           ring reservation -> parallel copy -> ordered drain
          |                                   ^ gap-free, or recovery truncates
     memtable apply       durable before visible
          |
     mark committed       now visible; hooks fire
          |
     maybe rotate         on this thread if it takes the lock; enqueue before swap
          |
     flush                demux to per-family sstables, one atomic manifest commit,
          |               installs ordered by ticket
     compaction           merge down; drop versions below min_snapshot_seq;
                          drop a tombstone only when nothing survives beneath it
```
