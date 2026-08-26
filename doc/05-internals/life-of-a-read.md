---
title: The Life of a Read
description: One get followed from the caller down through every source that could hold the key, and why the order is what it is.
slug: internals/life-of-a-read
part: internals
sidebar:
  order: 3
---

# The Life of a Read

A read has to answer one question — *what is the newest version of this key visible at this
snapshot?* — against data spread across a transaction's own buffer, memory, and several
tiers of files. This chapter follows one `tidesdb_txn_get` down through all of them.

The whole design turns on a single idea: **the sources are ordered newest-first, so the
first hit is the answer.** Everything else is the consequences of making that true and
keeping it true while other threads are writing, flushing, and merging.

## The snapshot decides what "visible" means

Before anything is searched, the transaction's snapshot fixes a sequence ceiling. A version
is visible if its sequence is at or below it.

| Isolation | Ceiling |
| --- | --- |
| `TDB_ISOLATION_READ_UNCOMMITTED` | Unbounded — everything, including sequences still in progress |
| `TDB_ISOLATION_READ_COMMITTED` | The current sequence, re-read per operation |
| Repeatable read and above | Frozen when the transaction began |

A sequence that has been drawn but not yet marked committed is invisible at every level
except read-uncommitted. That is what makes a multi-key batch atomic to readers without any
lock: the batch's sequence flips from in-progress to committed in one step, and until it
does, none of it can be seen.

## Stage 1 — The transaction's own writes

The transaction's write set is consulted first. A transaction always sees its own uncommitted
writes, and a key it has deleted reads as absent to it even though the tombstone is not
durable anywhere.

If the read is a tracking [`tidesdb_txn_get`](/reference/transaction#tidesdb_txn_get), the
key and the version found are recorded in the read footprint here. That record is what a
later commit validates against — see [The life of a write](/internals/life-of-a-write).

## Stage 2 — The source stack

Past the transaction's own state, the read walks an ordered list of sources:

```
  sources[0]   L0    the active memtable, then the sealed ones awaiting flush
  sources[1]   cf    dispatch into this column family's sstable levels
```

The walk stops on the first source that answers definitively:

```c,no-compile
if (r == TDB_SOURCE_FOUND || r == TDB_SOURCE_BUSY) return r;
```

`FOUND` stopping is the newest-first rule paying off. **`BUSY` stopping is the subtle part.**
A busy source is one that could not answer right now — a memtable slot being rotated out from
under the reader, an sstable whose descriptor budget is exhausted. Falling through to an
older source would find a *stale* version and return it as the answer, because the busy
source might have held a newer one. So contention is reported to the caller as
`TDB_ERR_LOCKED` and retried, rather than silently answered wrong.

This is why treating `TDB_ERR_LOCKED` as "not found" is a correctness bug and not merely a
missed retry.

## Stage 3 — L0: memory

The L0 source searches the active memtable, then each sealed memtable in the queue, newest
first.

Two hazards live here, both about a rotation happening underneath the reader.

**The memtable must not be freed while being read.** A reader pins what it loads: the active
slot is guarded by a reader epoch, and a sealed memtable carries a reference count. Reclaiming
a memtable waits for every reader to drop out. The pin is also what keeps a rotated memtable's
*write-ahead log* alive — rotation seals the memtable but does not drain its log's ring, so a
committer still waiting on that log holds the memtable to hold the log.

**The set of memtables must not appear to shrink.** Rotation enqueues the sealed memtable
before swapping the active slot, so at worst a reader sees it twice, never zero times. A
reader that walks the active slot and the queue non-atomically can still observe the set move
under it — there is a visible-change counter for exactly this, and the read re-snapshots and
retries rather than reporting a false absence.

Within one memtable the skip list holds a version chain per key. The read takes the newest
version at or below the snapshot ceiling. **A memtable version may hold a reference rather than
the bytes** — the commit separated it into the value log — and the L0 source resolves that before
answering, so what the layers above it see is always bytes. It asks the value log directly rather
than going back through this stack, which during recovery is reading the very memtables being
rebuilt.

 If that version is a tombstone, or its expiry
deadline has passed, the answer is a definitive **absent** — not a fall-through to older
sources. A tombstone shadowing an older value is the whole point of a tombstone.

One kind of version is stepped over rather than taken: a commit whose batch reached the log but
failed to enter memory leaves entries at a sequence that never committed. The chain walk skips
those and resolves to the next visible version beneath them, at every isolation level including
read-uncommitted, so a batch its caller was told had failed cannot be read back as the key's
value.

## Stage 4 — The level set

If memory has nothing, the read dispatches into the family's levels. Their shapes differ, and
the difference is not incidental:

- **L1 holds flush outputs, which may overlap in key range.** Two memtables flushed minutes
  apart can both contain the same key. So every L1 sstable whose key range covers the key must
  be consulted, newest first. L1 overlap depth is therefore a direct read-amplification cost,
  and it is what the L1 file-count trigger exists to bound.
- **L2 and below are non-overlapping runs sorted by minimum key.** At most one sstable per
  level can contain the key, and it is found by search rather than by scanning the level.

Levels are searched shallowest first, because shallower is newer. This is an invariant the
whole read path rests on, and it is why flush installs are strictly ordered — an out-of-order
install would place an older sstable above a newer one and quietly invert the answer.

The level set is read lock-free. Readers see an immutable layout under an epoch guard, and
the layout itself holds a reference on every sstable in it, so a compaction that replaces the
layout cannot free a table a reader is still inside.

A bitmap published with each layout says which levels hold anything, so a read skips the empty
ones without touching them. The mask is a **snapshot**, though, and the levels it does visit are
scanned against the live layout — so a merge that moves a table into a level the mask called empty
would be skipped while the level it came from reads as already emptied.

That is harmless when a **flush** did it: a flush installs its sstables and only retires the
memtable they came from afterwards, so through that whole window the keys are still in L0, which
every read consults first. It is **not** harmless when a compaction did it, because a compaction's
keys left L0 long ago and nothing backs them up. So the read records the layout generation before
the walk and checks it again on a miss; a shape that moved underneath reports a retryable busy
rather than an absence that was never true.

## Stage 5 — Inside one sstable

Three steps, arranged so the expensive ones are usually skipped.

**The partition range filter first.** A definite miss means the key is not in this table, and
the key log is never opened. Membership is version-agnostic — the filter answers about the
key, not about any particular version — so a miss is conclusive regardless of the snapshot.

**Then the descriptor budget.** Opening the key log needs a file descriptor, and the budget
is a soft ceiling. When it is exhausted the read does not force the open, and it does not hand
the shortage straight back either: the gate wakes the reaper and rechecks a bounded number of
times, so ordinary descriptor pressure is waited out inside the read. Only if it never clears
does the read report busy — the `BUSY` from stage 2, retryable backpressure rather than an
error, and by then the rare case rather than the routine one.

**Then the btree key log.** A search descends to the leaf holding the key. Leaves are
prefix-compressed with an indirection table over the key suffixes, and sequences are stored
as deltas from a per-node base, so a node holds many entries in little space. The search
resolves the newest version at or below the snapshot ceiling — the MVCC filter is native to
the btree rather than layered over it.

Every block read on this path goes through the database-wide block cache, keyed by the owning
file's id and the block's byte offset. Cache reads are lock-free: probe a slot, pin it with a
reference count, then recheck that the slot still holds what was probed. Entry slots are never
freed while pinned; only payloads are reclaimed, exactly once, by whichever thread drops the
last reference — evictor or reader, whoever is last.

The root is the exception, because every descent of a given key log starts at the same node.
Pinning it per descent would put every reader of that sstable on one reference count's cache
line, so the sstable reads its root once, holds that pin for as long as it is open, and lends
the node to each descent unpinned. The btree the descent runs on is built per read, and lives
far less long than the sstable holding the pin.

Only an internal root is held this way. A tree small enough that its root is also its leaf hands
that node straight back to a caller who releases what it is given, so it takes the ordinary
per-descent path instead. The cost of holding it is one node per open sstable that eviction
cannot reclaim until the sstable closes.

### A lapsed entry reads as a tombstone

A deadline is judged against the clock at the moment of the read, not against the reader's
snapshot: a transaction older than the deadline still sees the key gone. That is the rule the
memtable has always applied, and the sstable path applies the same one, because two rules would make
a key flicker depending on which source happened to answer it.

The clock they compare against is not `time(NULL)`. A ticker publishes the current second once a
second, and both the memtable's list and every sstable read that one published value. Reading the
system clock instead would mean a call on **every entry a scan touches**, which is the wrong place to
spend a syscall. The consequence is that a deadline is honoured within about a second of passing
rather than instantly — expiry is a visibility rule, not a timer — and that the second in question is
the same one for every source, which is what keeps them from disagreeing.

What it reads as matters as much as when. A lapsed entry answers like a **tombstone** — no value,
nothing to resolve out of the value log — and not like an absence. Reading it as absent would let the
source stack fall through to an older version of the same key in a deeper level, handing back a value
the overwrite had already replaced. Shadowing is also what carries it into a merge as a tombstone,
which is what eventually reclaims the bytes: the read only hides it.

## Stage 6 — Fetching a separated value

Small values are held inline. Larger ones — at or above the database's
`value_separation_threshold` — live in the shared value log, and whatever names them holds a
reference instead: a memtable version, an sstable entry, or a prepared batch waiting on its
decision. The committing transaction is what put them there, so a value is separated from the
moment it is written rather than from the flush that first persists it.

So a point read of a separated value costs a second I/O, while a scan that only needs keys
costs none at all. That asymmetry is the entire trade of key/value separation: it keeps the
btree small and scans fast, and it makes large-value point reads more expensive.
[`tidesdb_txn_contains`](/reference/transaction#tidesdb_txn_contains) exists so an existence
check need not pay it.

## What the read returns

The first definitive answer wins:

- a **live version** at or below the snapshot — its value, copied for the caller
- a **tombstone** or an **expired** entry — `TDB_ERR_NOT_FOUND`
- nothing anywhere — `TDB_ERR_NOT_FOUND`
- a **busy** source — `TDB_ERR_LOCKED`, meaning *ask again*, not *absent*. Rare, because the
  pressure that produces it is waited out inside the read before it is reported

## The whole path

```
  snapshot ceiling fixed by isolation level
          |
  transaction write set            own writes, own tombstones; read recorded here
          |
  +-- source stack, newest first -- first FOUND or BUSY wins --------------------+
  |                                                                              |
  |  L0   active memtable            epoch-pinned; version chain, newest <= snap |
  |       sealed memtables           ref-counted; enqueue-before-swap            |
  |            |                                                                 |
  |            +-- value log                only if the value was separated      |
  |                                                                              |
  |  cf   L1  overlapping            every covering table, newest first          |
  |       L2+ non-overlapping runs   at most one table per level                 |
  |            |                                                                 |
  |            +-- partition range filter   definite miss -> skip the table      |
  |            +-- descriptor budget        waits out pressure; BUSY if it stays |
  |            +-- btree key log            newest version <= snapshot           |
  |            +-- value log                only if the value was separated      |
  +------------------------------------------------------------------------------+
```

Read amplification is the number of sources this walk actually touches, and the filters are
what keep it near one. `read_amp` in
[`tidesdb_get_cf_stats`](/reference/statistics#tidesdb_get_cf_stats) estimates it, and it is
the number to watch when reads slow down.
