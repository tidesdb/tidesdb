---
title: File Descriptor Manager
description: A descriptor budget that turns exhaustion into retryable backpressure instead of failure.
slug: internals/fd-manager
part: internals
sidebar:
  order: 11
---

# File Descriptor Manager

## The problem

An LSM database accumulates files. A few thousand sstables is ordinary, and every one a reader
touches needs an open descriptor. The process has a hard ceiling on those, often 1024 by
default, and it is shared with everything else the embedding application is doing.

Left alone this fails in the worst possible way. Descriptors run out during a flush or a
compaction — precisely when the database is busiest — and the failure surfaces as `EMFILE`
from an `open` deep inside an unrelated code path. Nothing about that error tells the caller
the situation is temporary, so it propagates as an I/O failure and a perfectly healthy
database reports corruption-shaped errors under load.

The manager exists to turn that into something with a defined meaning: **descriptor exhaustion
is backpressure, and backpressure is retryable.**

## A standalone service

It owns no engine and reaches into no global handle. A caller constructs one, opens block
managers through it, and gates reader opens against it. It is unit-testable with a
stack-allocated instance and no database anywhere — the same
[composition rule](/internals/architecture) the rest of the engine follows.

## Labels over one budget

Every tracked descriptor carries a **label** naming its file kind:

| Label | File |
| --- | --- |
| `FD_LABEL_SSTABLE_KLOG` | An sstable's key log |
| `FD_LABEL_WAL_LOG` | A write-ahead log |
| `FD_LABEL_VLOG_SEGMENT` | A value-log segment |

Counts are kept per label while **one shared ceiling** bounds the total. The split matters
because the kinds are reclaimed differently and by different logic: an idle key log or value-log
segment can be closed and reopened on the next read, while an active write-ahead log's descriptor
cannot. Labelling lets the right reaper reclaim the right kind without one starving the other.

**Value-log segments are held to the same ceiling.** The store is a series of segment files rather
than the single file it once was, and a large database can hold thousands of them, so leaving them
outside the budget would let the value log exhaust the process on its own while the reported figures
looked healthy.

The reaper takes segments back **before** key logs. A key log is read on every point lookup that
reaches its sstable, while a segment is touched only when a separated value is dereferenced, so of
the two the segment's descriptor is more likely to be sitting idle. Neither loses anything by being
evicted — both reopen on the next read — and the segment currently taking appends is never taken,
since it is written on every spill and would be reopened immediately.

**The budget is not `max_open_sstables`.** A reserve is held back so a reader can still open a file
while the reaper is working: an eighth of the configured maximum, never fewer than 16 descriptors
and never more than half of it, subtracted from the maximum and floored at one. At the default
`max_open_sstables` of 1024 that reserves 128 and leaves a **budget of 896** — the count the reaper
reclaims toward and the point at which readers begin to be gated, both of which arrive before the
configured number is reached.

A maximum of **0 means unlimited** to the manager itself: no soft cap, so the reaper never evicts for
budget, no reader is ever gated, and resident descriptors are bounded only by the process open-file
limit — where exhaustion surfaces through the `EMFILE` retry path below rather than as backpressure.
That state is not reachable by configuring `max_open_sstables` to zero, because `tidesdb_open`
[resolves a zero there to the default](/appendix/configuration) before the manager is constructed.
It is what a caller building a manager directly gets, which is how the unit tests exercise it.

Not everything is labelled. The manifest and stdio are not tracked at all, and neither are
temporaries. Those, plus headroom, are what the fixed `TDB_FD_RESERVE_UNTRACKED` of 64 descriptors
is held back for.

**The budget is cut to fit the process at open.** `tidesdb_open` reads the open-file ceiling and
calls `fd_manager_budget_for_process`, which lowers `max_open_sstables` until it leaves that reserve
free, logging at warn when it does. This matters at the defaults and not only at the extremes: the
default `max_open_sstables` is 1024 and the usual POSIX default `RLIMIT_NOFILE` is *also* 1024, so a
database left alone would budget every descriptor the process has and leave none for the manifest it
must also hold. The ceiling is only ever read — raising it is
[`tidesdb_raise_open_file_limit`](/reference/database#tidesdb_raise_open_file_limit), an operator's
call, made before open.

The cut is deliberately conservative about what it will act on. A ceiling that is unlimited, that
cannot be read, or that the platform cannot state exactly — Windows, whose low-IO layer permits a
large but unqueryable number of handles — reports as *no ceiling*, and the configured figure stands.
Cutting against a guess would penalise precisely the process that had no limit at all.

The reader gate therefore asks one question — whether the resident total is under the budget — and
not two. An earlier design kept a second, process-wide descriptor count behind it, fed by an
observer on every block-manager open and close. It was never armed, and cutting the budget to fit
the process is what made it redundant rather than merely unused: the budget now sits at or below
`ceiling - reserve`, so the resident check reaches its limit first, always.

What that leaves uncovered is **several databases in one process**. Each cuts against the same
ceiling independently, so together they can still exceed it. A shared count would notice, but it
would not help: each database's reaper reclaims only its own files, so the one that gets gated would
wake a reaper with nothing of the offender's to close, wait out its rechecks and fail regardless.
That case belongs to the `EMFILE`/`ENFILE` retry path below, and sizing several databases to share a
process is the operator's to do.

:::caution[Every labelled open must pair with a labelled close]
The counts are maintained by the code that takes and releases ownership of a file, not by the
block manager underneath it, because only the owner knows which kind of file it is holding.
That makes the pairing a standing obligation rather than something the type system enforces.

An unpaired close is worse than it sounds. The two readers of these counts —
the reader gate and the reaper — both look at the **total across every label**, so one label
drifting drags the total with it. A count that only ever decrements eventually pushes the total
below zero, at which point the gate admits every open and the reaper's reclaim loop never
executes: the budget silently stops existing while every statistic still reports a sensible
number, because the reported figure reads a single label rather than the total.

Key logs are accounted where the sstable adopts and releases them. Write-ahead logs are
accounted in `engine_open_wal` and `engine_close_wal`, and the flush path — which retires a
generation's log after its data reaches L1 — is the one other place permitted to release one.
A new close site that bypasses those is the way this breaks.
:::

## Two ways it applies pressure

**A reader gate.** Before an sstable read opens a key log, it asks whether the budget allows
it. If it does not, the gate does not hand the problem back — it wakes the reaper to close idle
files, waits briefly, and rechecks, a bounded number of times. Descriptor pressure under a heavy
flush and compaction load outlasts a single recheck, and a caller told to try again has no lever
the engine does not already have: its only remedy is to sleep and ask again, which is what the
gate does on its behalf, knowing what it is waiting for.

Only when every recheck fails does the read report **busy** — the `TDB_SOURCE_BUSY` of
[the read path](/internals/life-of-a-read), which the public boundary translates to
`TDB_ERR_LOCKED`. That is the exhausted case rather than the ordinary one, and it is still why
treating the code as "not found" is a correctness bug. The data exists; only the descriptor was
unavailable.

**Open retry.** Opening a block manager can still hit the real process ceiling under heavy
flush and compaction, since not every descriptor in the process is tracked. The open wrappers
treat `EMFILE` and `ENFILE` the same way, and to the same bound: wake the reaper, back off
briefly, retry. Both paths absorb the same pressure identically, which matters because they
compete for the same descriptors — a reader that gave up sooner than an opener would turn a
shortage one of them was about to clear into a failure the caller had to understand.

Both bounds are finite. If the ceiling is genuinely exhausted by something outside the database,
retrying forever converts a resource problem into a hang.

## The reaper

A background ticker closes idle descriptors back down toward the budget. Readers signal it when
they are gated, so pressure is relieved on demand rather than only on a timer.

Closing a descriptor does **not** evict the sstable. The object stays installed and readable;
only its file handle goes. The next read reopens it. This is the distinction drawn in
[SSTable](/internals/sstable) — object lifetime and descriptor lifetime are separate — and it
is what makes a descriptor safe to reclaim at all.

The reaper must not close a descriptor a reader is inside. An installed sstable rests at one
reference — the one its level set holds — and the sweep takes a second on every candidate it
collects, so a table with no reader in flight is sitting at **both**. That total is what the
evicting window is claimed at, and anything above it means someone is using the file.

Counting only the level set's reference is not a smaller mistake than counting none: the claim is
an exact compare-and-exchange, so a resting count named one short simply never matches, and no key
log is ever given back while the statistics go on reporting a budget that is quietly not being
enforced.

The window itself has to survive whatever runs during it. It is claimed by moving the reference
count to a sentinel and released by adding that offset back rather than storing the resting value,
so a reference taken or dropped inside the window carries through. Storing it would discard that
thread's change — losing an acquire frees a file still being read, losing a release leaks the
handle for the life of the process.

The sweep also passes over any table whose descriptor is already closed. A database keeps far more
sstables than it keeps open, and one with nothing resident has nothing to give back, so ordering it
by age and offering it for eviction is work spent on a table that cannot answer.

## Why this is a module and not a counter

It could have been an atomic counter checked before `open`. It is a module because the
behaviour that matters is not counting but **what happens at the limit**: which kind is
reclaimed, who is woken, how long a caller waits, how many times it retries, and what it
reports when it gives up. Those are policy decisions, and putting them in one testable place is
what keeps them consistent across the flush path, the compaction path, and the read path.

## Invariants

| Invariant | Why |
| --- | --- |
| Every labelled open pairs with a labelled close | Both readers of the counts use the cross-label total, so one drifting label disables the budget entirely |
| Pressure is waited out before it is reported | The caller's only remedy is to sleep and retry, and the engine can do that better because it knows what it is waiting for |
| Exhaustion is reported as busy, never as absent | The data exists; only the descriptor is unavailable |
| A descriptor is reclaimed only at the resting reference count, the level set's plus the sweep's own | Any excess reference means a reader is inside the file. The claim is an exact match, so a resting count named one short never fires at all and the budget stops being enforced silently |
| The evicting window preserves a reference taken or dropped inside it | The sentinel is a fixed offset, so releasing by adding it back carries the change through; storing the resting value would free a file still being read, or leak the handle |
| Closing a descriptor never evicts the sstable | The object and its file handle have separate lifetimes |
| Reader-gate rechecks and `EMFILE`/`ENFILE` retries are bounded, and to the same bound | An externally exhausted ceiling must fail, not hang; and a reader that gave up sooner than an opener would fail on a shortage the opener was about to clear |
| The budget plus the untracked reserve fits the process limit | Untracked files must not be starved by tracked ones. `tidesdb_open` cuts `max_open_sstables` through `fd_manager_budget_for_process` so the reserve is always left free. Bounds one database; several in one process cut against the same ceiling independently and can still exceed it together |
