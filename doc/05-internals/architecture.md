---
title: Architecture
description: How TidesDB is put together -- the composition root, the module map, and the rule that keeps the pieces separable.
slug: internals/architecture
part: internals
sidebar:
  order: 1
---

# Architecture

TidesDB is a log-structured merge-tree. Writes go to memory and a log; memory fills and is
written out as a sorted file; files accumulate and are merged. Everything else in this part
is detail on those three sentences.

This chapter is the map. The two that follow it walk the whole system twice — once
[following a write](/internals/life-of-a-write), once
[following a read](/internals/life-of-a-read) — and after that each subsystem gets a chapter
of its own. Read the three in order and the rest can be read in any order.

## One rule shapes the whole codebase

**No module below the engine takes a `tidesdb_t`.**

The database handle is the composition root's own type. The memtable does not know what a
column family is; the block manager does not know what a memtable is; the compaction planner
does not know what a file is. Each module takes the narrow set of things it actually needs
and is constructed by the layer above it.

The immediate payoff is testability. The compaction planner is a pure function over a
snapshot of level sizes — no I/O, no handles, no clock — so it is tested by handing it
numbers. The block manager is tested against a temp file with no database anywhere. The fd
manager is tested with a stack-allocated instance. A module that reached for a global
database handle could not be tested this way, and in practice would not be tested at all.

The longer-term payoff is that the seams stay honest. When a module needs something it was
not given, that is a design question surfaced at the function signature rather than a field
quietly read from a global.

## The layers

```
    tidesdb_txn_commit()                     public API      include/db.h
            |
    src/db.c                                 facade          argument checks, opaque-type casts
            |
    src/engine/                              composition     owns tidesdb_t, wires everything
            |
  +---------+---------+---------+---------+
  |         |         |         |         |
 txn/    memtable/  sstable/  compaction/ ...            subsystems, none aware of tidesdb_t
  |         |         |         |
  +---------+---------+---------+
            |
    src/io/, src/base/, src/platform/        foundations     blocks, atomics, portability
```

`src/db.c` is deliberately thin. It validates arguments, casts the opaque public types to
their internal ones, and forwards. Nothing decides anything there, which is why the public
API can be read as a list of intentions and the engine as a list of mechanisms.

## Module map

| Directory | Responsibility |
| --- | --- |
| `src/engine/` | The composition root. Owns `tidesdb_t`, open and close, recovery, the worker pools, and the orchestration of flush and compaction. |
| `src/txn/` | Transactions, MVCC sequences and snapshots, write and read sets, conflict reservations, two-phase commit, WAL record encoding, and the L0 adapter binding the txn core to the memtable. |
| `src/memtable/` | The one shared in-memory write buffer and its write-ahead log, rotation, the immutable queue, and reader-pinned reclamation. |
| `src/sstable/` | The on-disk sorted table: a btree key log, the shared value log, the partition range filter, and a self-describing footer. |
| `src/column_family/` | Family configuration, the registry, and the level set that organises a family's open sstables into tiers. |
| `src/compaction/` | The Spooky planner (pure, deterministic) and the executor that runs the jobs it emits. |
| `src/flush/` | Turning one sealed memtable into per-family L1 sstables under a single atomic manifest commit. |
| `src/manifest/` | The durable catalogue of what exists, shared by every family so a flush across families is atomic. |
| `src/iter/` | The k-way merge over a versioned source vtable that backs every iterator and every compaction. |
| `src/cache/` | The database-wide block cache every on-disk block read goes through. |
| `src/fdmanager/` | A descriptor budget that waits out file-descriptor pressure inside the engine, so exhaustion becomes backpressure instead of failure. |
| `src/io/` | The block manager: framing, durability, preallocation, and the buffered append ring. |
| `src/datastructures/` | The skip list backing the memtable, and the queue backing the work queues. |
| `src/base/` | Errors, logging, serialization, arena allocation, and the lock-free reclamation primitives everything else uses. |
| `src/internal/` | The memtable type and the two tombstone flag bits the write path carries from the memtable down into an sstable. |
| `src/platform/`, `src/threadmanager/` | Portability and thread pools. |

## What is shared and what is per-family

This distinction explains a great deal of behaviour that is otherwise surprising, so it is
worth fixing early.

**Shared by the whole database:** the memtable, the write-ahead log, the value log, the
manifest, the block cache, the descriptor budget, and the sequence clock.

**Per column family:** the level set and its sstables, the compaction policy and triggers,
and the family's configuration.

One shared memtable is why a transaction spanning several families is atomic — there is one
log and one apply. It is also why
[`tidesdb_flush_memtable`](/reference/maintenance#tidesdb_flush_memtable) flushes everything
rather than one family, and why cloning a family costs a database-wide flush — the clone copies
files, so every committed write has to be in one first. Renaming costs no flush, because a family
has no directory of its own — every key log sits in the database directory carrying its family's
**id** in its file name, so a new name moves nothing.

Keys are namespaced inside the shared structures by a four-byte big-endian family index
prefix, so one skip list and one log hold every family's data in one ordered space.

### The family registry

The families live in a registry that separates two questions that used to share one lock: *which
families exist*, and *may this family's handle still be used*.

Almost everything reads that membership: every flush build and install, every compaction claim,
every reaper sweep, every statistics fold. Under load these arrive continuously, and none of them is
the caller's work. Only `create`, `drop`, `rename` and `clone` change it, and those are exactly the
operations a user issues and waits on.

That asymmetry is fatal to a reader-writer lock. A reader-writer lock admits an arriving reader
while a writer waits, so a database whose background work never stops never produces the gap the
writer needs -- the writer is not slow, it never runs. Announcing the waiting writer so arriving
readers hold off narrows the window but does not close it: the writer still has to be handed the
lock, and on a platform whose scheduler does not do that promptly under contention, a
`CREATE TABLE` sits for minutes at a full core. That reads as a deadlock and is really starvation.

So the readers do not take a lock at all. The registry publishes an **immutable view** of its
membership, and a reader borrows it. A borrow is two-stage, and the split is the point: a short
guard covers only the few instructions between reading the published pointer and counting the
borrow, while a **reference count on the view itself** covers the long hold -- a flush build, which
runs for as long as its I/O takes. A membership change publishes a new view, so borrows arriving
afterwards take that one and an unpublished view's count only falls. Waiting for those counts to
reach zero therefore terminates however busy the readers are, which waiting for *no reader at all*
could not.

The wait is on **every** view a departing family was named by, not just the one the change
displaced. A borrow can be holding an older view still -- a flush borrows one, a create publishes
over it without waiting, and a later drop that waited only on what *it* displaced would free a
handle that flush is still using. The registry therefore counts the views it has allocated, and a
removal waits until only the published one is left, holding the registry meanwhile so nothing can
publish another.

The lock that remains is a plain mutex, and only the four membership changes take it. They contend
with each other and with nothing else, so there is no stream for a writer to lose to.

Lifetime follows from the same mechanism. `drop` publishes a view without the family, waits out the
borrows that could still name it, and only then frees the handle -- the wait the read lock used to
provide implicitly. A family's mutable fields work the same way rather than being written in place:
its name is published and the old one retired, because a flush copies that name onto an sstable
where it is the first component of a block-cache key, and a torn copy is a wrong key rather than a
cosmetic defect. A clone swaps its destination's level set while that family is unpublished, since
the compaction scheduler reads every published family's overlap depth whether or not it is claimed.

Two things follow from the same reasoning. A flush waits for its install ticket *before* it borrows
the view, never while holding one -- borrowing across the wait would stretch one worker's hold to
cover every flush queued ahead of it. And a flush never waits for a reader to leave in order to free
a memtable; it hands the memtable to the reaper instead. See
[Memtable and WAL](/internals/memtable-and-wal#reclaiming-a-sealed-memtable).

## Threads

| Thread | Work |
| --- | --- |
| Caller threads | Everything on the transaction path: buffering, conflict checks, WAL append, memtable apply. A commit does its own work rather than handing it to a worker. |
| WAL flush thread | One per open write-ahead log. The only thread that writes that file. |
| Flush pool | Turning sealed memtables into sstables. Sized by `num_flush_threads`. |
| Compaction pool | Merging sstables. Sized by `num_compaction_threads`. |
| Reaper | Closing idle file descriptors back down to the budget, and reclaiming what the paths that produced it could not free inline -- drained level-set layouts, and sealed memtables a flush had to leave pinned. |
| Compaction scheduler | Reconsidering every family for a merge once a second, so a family still becomes due without a flush to wake it. |
| Idle flush | Rotating an active memtable nothing has written to, unless `memtable_idle_flush_seconds` is zero. |
| Transaction clock | Publishing the current second, once a second, for transaction timeouts to age against. |
| Sync ticker | Under `TDB_SYNC_INTERVAL`, the periodic durability barrier. |

Rotation is the interesting case: it runs on **whichever committing thread finds the
memtable full**, not on a worker. That thread pays the latency, and every other committer
that agrees waits behind the same lock — which is why a slow rotation shows up directly in
the write latency tail, and why the engine logs one when it exceeds
`ENGINE_SLOW_ROTATE_WARN_US`.

## Where the durability guarantees come from

Three files carry everything, and the order they are written in is the whole recovery story:

1. **The write-ahead log** (`NNNNNNNNNNNN.log`) takes a committed batch before the memtable does.
   A crash between the two recovers the batch.
2. **The sstables** (`CCCCCCCCCCCC.SSSSSSSSSSSS.klog`, named for the owning family's id and the
   table's) and the **value log** (`NNNNNNNNNNNN.vlog` segments) hold what has been flushed. They are durable
   before the manifest names them.
3. **The manifest** (`MANIFEST`) is the catalogue. A file it does not name does not exist as
   far as recovery is concerned, so a crash mid-flush leaves orphans rather than corruption.

Each of those is a block manager file with the same framing, so one recovery discipline
covers all of them. The [appendix](/appendix/formats) has the byte layouts.
