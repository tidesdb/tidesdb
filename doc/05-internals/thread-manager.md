---
title: Thread Manager
description: One owner for every background thread the engine runs, so shutdown is ordered and observable.
slug: internals/thread-manager
part: internals
sidebar:
  order: 12
---

# Thread Manager

## The problem

The engine runs several kinds of background work: worker pools draining queues, and periodic
tickers. Each needs the same lifecycle — create threads, signal shutdown, wake anything
blocked, join, and account for the ones still alive.

Hand-rolling that per subsystem is how shutdown bugs are made. Each site invents its own stop
flag and its own join, they drift, and a thread that blocks on a queue nobody will ever post
to becomes a hang at close. Worse, the *order* of shutdown ends up implicit: whichever pool
happens to be stopped first.

So the pthread lifecycle lives in two primitives, and one registry owns every instance.

## Two primitives

**A worker pool** is a fixed set of threads that each block on a shared queue and hand every
dequeued item to a callback. The queue is **caller-owned** — the pool neither creates nor frees
it. That separation is what lets the engine shut a pool down and still hold the queue to drain
whatever was left in it.

**A ticker** is a single thread that runs a callback once per interval and can be woken early.
The tick runs *first*, then the thread waits — so a ticker started to do something does it
immediately rather than after one interval. Wakeability is what lets a reader nudge the fd
reaper the moment it is gated instead of waiting out the period.

Neither primitive knows anything about databases. Both are constructed with a callback and a
context.

## The registry

Every background process is registered under a **label**:

| Kind | Instances |
| --- | --- |
| Pool | flush, compaction |
| Ticker | the transaction clock, the descriptor reaper, deferred frees, and the compaction scheduler — always; idle rotation unless `memtable_idle_flush_seconds` is zero; WAL sync only under `TDB_SYNC_INTERVAL` |

The registry owns the handles and stops them. It does **not** own the queues a pool drains —
those belong to the engine, which needs them after the workers are gone.

Two properties come out of having one owner:

**Shutdown is ordered.** Processes are stopped in reverse registration order, so a subsystem
started later — and therefore possibly depending on an earlier one — is stopped first. Ad-hoc
shutdown gets this right by luck; a registry gets it right by construction.

**Background work is enumerable.** One place can answer what is running, which is the
difference between diagnosing a stuck close and guessing at it.

## Shutdown

Closing a database drains and stops in order:

1. Stop accepting new work.
2. Stop the background processes in reverse registration order — each signalled, woken if
   blocked, and joined.
3. Drain what remains: sealed memtables still queued are written out, or their logs are closed
   without unlinking so the data survives to be recovered.
4. Release the shared stores.

Step 3 is where the ordering earns itself. Draining the flush queue requires that no worker is
still pulling from it, and that no compaction is still installing into a level set being torn
down.

:::note[Close cannot report a failure]
The shutdown path returns no status, so
[`tidesdb_close`](/reference/database#tidesdb_close) always succeeds for a live handle. An I/O
error while writing the last of the data is logged, not returned. Callers needing a durability
guarantee ask for one before closing.
:::

## What runs where

Worth stating plainly, because it explains where latency comes from:

| Work | Thread |
| --- | --- |
| Buffering, conflict checks, WAL append, memtable apply | The calling thread |
| **Rotation** | The committing thread that found the memtable full |
| Writing a sealed memtable to sstables | Flush pool |
| Merging sstables | Compaction pool |
| Writing a buffered file to its descriptor | That file's own flush thread |
| Closing idle descriptors | Reaper ticker |
| Freeing memtables and level layouts a reader still held when they were retired | Deferred-free ticker |
| Deciding which families are due a merge | Compaction-scheduler ticker |
| Rotating a memtable nothing has written to | Idle-flush ticker |
| Publishing the second transaction timeouts age against | Transaction-clock ticker |
| Periodic durability barrier | Sync ticker |

## What an idle database costs

An open database taking no traffic should approach zero CPU, and treating that as the signal the
engine has quiesced is reasonable — so anything that keeps the process warm is a defect rather than
a detail.

The tickers are cheap by construction. Each parks on a condition variable with a deadline rather
than polling, and the ones that are conditional are not started at all when nothing asks for them.

A deadline is an absolute time, so the clock it is read from decides what the wait means. Where a
condition variable can select its clock the engine gives it the monotonic one and builds the
deadline from the same, so the two agree. A wall clock that steps forward or back would otherwise
leave every parked thread waiting for a time that has moved away from it, and since the background
workers all park in the same place, they stop together and for the length of the step. macOS has no
way to select the clock, so there both the variable and its deadlines stay on the wall clock, which
at least keeps them consistent with each other.
Four run once a second — the transaction clock, the descriptor reaper, deferred frees and the
compaction scheduler — so that is four wakeups a second in the usual configuration and five under
`TDB_SYNC_INTERVAL`, plus idle rotation on its own far longer period, thirty seconds by default.
None of that registers.

The thing that did register was a **buffered file's flush thread**, which is not a ticker and does
not appear in the table above as periodic work. Its park timeout was short enough to wake it two
thousand times a second whether or not anything had been written, which is most of an idle
process's CPU. The timeout is only insurance against a missed wake, never the mechanism that
delivers work, so it now grows while parks come up empty and resets the moment a run drains — see
[Block Manager](/internals/block-manager).

Being insurance is also why its park reads the clock the tickers do. The timeout decides anything
only when a wake was missed, which is exactly the moment a deadline built on a clock that has since
stepped has nothing behind it — and this is the single thread that drains the ring, so a flush
worker retiring a memtable and every committer waiting on durability wait for however long the step
was.

The lesson generalizes. A periodic *fallback* alongside an event-driven path should be sized for
the rare case it exists to catch, not for the latency of the common case, because the common case
is already covered by the signal.

## What does not run on a worker

A commit does its own work rather than handing it to a worker, so commit latency is the work
itself plus contention — not a queue depth. Rotation is the exception that proves the rule: it
runs on a committing thread, which is exactly why a slow one lands in the write latency tail
and is logged when it exceeds `ENGINE_SLOW_ROTATE_WARN_US`.

## Invariants

| Invariant | Why |
| --- | --- |
| One registry owns every background process | Otherwise shutdown order is implicit and drifts |
| Processes stop in reverse registration order | A later subsystem may depend on an earlier one |
| A pool never owns the queue it drains | The engine needs the queue after the workers are gone |
| Every stop signals, wakes, and joins | A thread blocked on an empty queue would hang the close |
| A ticker runs its tick before its first wait | Startup work must not be delayed by a full interval |
