---
title: Memtable and Write-Ahead Log
description: The one shared write buffer, its log, rotation, backpressure, and reader-pinned reclamation.
slug: internals/memtable-and-wal
part: internals
sidebar:
  order: 4
---

# Memtable and Write-Ahead Log

## The problem

A write must become durable quickly and become queryable immediately, and those two demands
pull in opposite directions. Durability wants sequential appends to a file. Queryability
wants an ordered structure that can answer a lookup. Doing both per write would mean writing
a sorted file on every commit.

The standard resolution is to do each separately: append to a log for durability, insert into
an in-memory ordered structure for queryability, and periodically turn the accumulated memory
into one sorted file. The log exists only to survive the gap between "committed" and "written
out as a sorted file".

TidesDB adds one decision on top: **there is exactly one memtable for the whole database**,
not one per column family.

## Why one shared memtable

A transaction may touch several column families and must be atomic across all of them. With
one memtable and one log, that atomicity is free — a single log record, a single apply. With
per-family memtables it would require a commit protocol across them.

The cost is that the memtable is a shared resource. Flushing is database-wide because there
is only one thing to flush, which is why
[`tidesdb_flush_memtable`](/reference/maintenance#tidesdb_flush_memtable) has no per-family
form and why cloning a family pays a full flush -- a clone copies files, so everything it should
copy has to be in a file first. Renaming does not: a family's files are named for its immutable id,
so a rename moves nothing and needs no flush at all.

Families are kept apart inside the shared structures by prefixing every key with a **4-byte
big-endian family index**. One ordered keyspace holds every family, and each family's keys
form a contiguous run within it. Flush exploits exactly this: demultiplexing the shared
memtable into per-family sstables is a walk in order, splitting at prefix boundaries.

### A flush retains against the same floor a merge does

A memtable holds a version chain per key. The flush walks all of it, and the **reclamation floor**
decides what survives: every version above the floor, and the newest at or below it as the base.
That is the rule a merge already applies, asked here too.

With no transaction registered the floor sits at the top, nothing is above it, and the newest
version takes the base. An ordinary flush therefore writes one version per key and costs nothing
extra. It carries more only while a reader holds a snapshot underneath one.

:::caution[Taking only the newest version silently breaks a frozen snapshot]
The floor exists because a reader can be sitting below an overwrite. A flush that wrote the newest
version alone would drop every older one whatever the floor said, and a repeatable-read transaction
whose snapshot sat below an overwrite would then find the key **absent** — not stale, absent, which
is a live key reading as missing.

It is easy to miss because the floor is computed, published and honoured by compaction, so the
protection looks like it is already there. Flush is the other half of the write path and has to ask
the same question. The default isolation level re-reads on every operation and so never notices,
which is why this survived: it needs a frozen snapshot, an overwrite, and a flush together.
:::

One difference from a merge: a flush writes into L1, never the largest level, so it never drops a
base tombstone. A tombstone at the shallowest tier is what shadows older versions in the levels
below it, and dropping one there would bring a deleted key back.

## Structure

A memtable is a pair — an ordered structure and the log that makes it recoverable — plus the
state needed to retire it safely:

```
  skip_list        the ordered structure; a version chain per key
  wal              the block manager for this generation's log
  id, generation   identity; the generation names the log file
  refcount         structural + transient reader references
  writers          an epoch guarding in-flight writers
  flushed          set once the data is durable in L1
  claimed          set when a flush worker has taken it
  vlog_token       a value log floor, for the values only this memtable names
  range_tombstones the intervals deleted in this generation, with their own lock and a
                   published fragment count so a read that needs none never takes it
```

The range tombstones sit beside the skip list rather than in it, because they are not keyed by
anything the list is sorted on — an interval covers keys that may not exist yet. They are stored
over the same family-prefixed keyspace, so one set serves every family, and a memtable that has
never taken a [range delete](/reference/transaction#tidesdb_txn_delete_range) costs a count of zero
that every read short-circuits on.

The skip list stores a **version chain per key** rather than one value: several versions of
the same key coexist, each with its sequence, and a read takes the newest at or below its
snapshot. That is what makes MVCC work in memory without copying the structure per snapshot.

**A version holds either the value or a reference to it.** A value at or above the database's
`value_separation_threshold` is written to the [value log](/internals/value-log) by the committing
transaction, and the version keeps the id and the value's logical length in place of the bytes. A
read that lands on one resolves it through the value log; the flush that follows carries the id into
the sstable rather than writing the bytes a second time.

That makes the memtable the only thing naming those values until its flush installs, so it takes a
value log floor over their segments — `vlog_token` above — held from the moment it becomes the
active memtable until that install. Taken then rather than at its first reference, because a value
reaches the value log before the commit that produced it reaches any memtable.

### The active memtable and the queue

At any moment there is one **active** memtable taking writes, and a queue of **sealed**
memtables that are full and awaiting flush. Reads consult the active one first, then the
queue newest-first — see [The life of a read](/internals/life-of-a-read).

The log file is named for the generation, `NNNNNNN.log`, zero-padded, so the set on disk
sorts into replay order by name alone. Recovery needs no sidecar index to know what to replay
or in what order.

## Rotation

When a write fills the active memtable, the committing thread that noticed rotates it. Not a
background worker — the thread that filled it.

**What "fills" means is every version, not every key.** A memtable holds a version chain per key, and
nothing prunes a chain before the whole memtable is freed — an overwrite adds a version rather than
replacing one, because a reader at an older snapshot may still need the version being superseded. So
the size the rotation threshold reads has to count every version resident, and a key written a
thousand times occupies a thousand versions' worth of it.

The range tombstones count toward that size too. Without them a memtable holding nothing but
interval deletes would measure as empty, and neither the size trigger nor the idle flush would ever
seal it — so the deletes would sit in memory with no flush to make them durable.

A version's cost is its own structure plus whatever value it carries, so a tombstone is not free —
it carries no value but is still a resident allocation, and a key deleted repeatedly grows its chain
just as surely as one overwritten repeatedly. The same holds for a put of an empty or tiny value,
which is what a secondary index entry usually is.

**And what it reads is memory, not data.** A distinct key costs a skip list node, two pointer arrays
sized by the level its coin flips gave it, and the key bytes, laid down in one allocation; its first
version costs a version struct and the value bytes, in another. That comes to about 100 bytes an
entry beyond the key and the value, and it does not move with entry size — so it is most of an entry
holding an 8 byte value and under 3% of one holding a 4 KiB value.

A referenced version carries eight bytes of id where an inline one carries the value, so a memtable
of separated values holds vastly more keys before it fills — which is most of what separation buys
on the write path, beyond the bytes it saves.

Counting only key and value bytes therefore understates a memtable of small entries by about five
times, and a store configured for 64 MiB would quietly hold 300 MB and more, multiplied again by
however deep the immutable queue is allowed to get. The threshold reads the memory figure, so
`memtable_write_buffer_size` is a budget on memory occupied rather than a promise about the size of
what a rotation flushes. The two counters are kept apart for that reason: the flush path sizes its
key log preallocation from the data bytes, which is what it is about to write, while rotation and
backpressure read the memory bytes, which is what the host is actually paying.

Counting only the newest version per key, or counting a version by its value alone, would be the
same bug in a different disguise every time:
the memtable would report a size that never reaches the threshold, never seal, and grow until the
host ran out of memory — while every statistic the engine reports stayed flat, because they would
all be reading the same understated number. A workload of distinct keys would look perfectly healthy;
only repeated writes to the same keys would show it.

That choice is visible in latency: a rotation is real work on the write path, and every other
committer that agrees the memtable is full waits behind the same lock. A slow one lands
directly in the write latency tail, which is why the engine logs any rotation that exceeds
`ENGINE_SLOW_ROTATE_WARN_US`.

**The log the rotation installs is opened before the rotation needs it.** Opening one costs a file
creation, a staging ring and a flush thread. Paid inline, that is orders of magnitude more than the
slot swap it accompanies — and every committer in the database is stopped for the whole of it, since
the rotation holds the lock while it works. How much more depends entirely on the filesystem and the
device: it has been measured from tens of milliseconds on a local SSD to well over a hundred on a
virtualised runner with no working preallocation. A log is therefore prepared after each rotation,
outside the lock, and the next rotation
takes the prepared one and becomes a memtable allocation and two pointer swaps. The preparing thread
still pays the cost; the other fifteen no longer do.

Preparing is claimed, not merely checked. Every committer that rotated arrives at the same moment
and the empty-slot check is only a hint, so without a claim each one creates a log for a slot that
holds one, and all but the winner abandon theirs. A log that loses the race is unlinked as well as
closed, and so is a prepared log the database never rotated into before closing. An abandoned log
is not inert: the next open scans it, replays it, and gives it a memtable in the L0 queue, so one
left behind costs work on every open thereafter for records it never held.

The order inside a rotation is not adjustable:

1. **Enqueue** the sealed memtable.
2. **Swap** in a fresh active memtable.

For an instant the sealed memtable is reachable both as the active one and in the queue. That
is harmless — a reader that finds it twice gets the same answer. The reverse order is not
harmless: between the swap and the enqueue there is a window where the memtable is in neither
place, and a reader would report a live key as absent.

:::caution[Rotation does not drain the log]
Sealing a memtable does not flush or close its write-ahead log. A committer may still be inside
that log when the rotation happens — waiting for its record to reach the file under interval and
full durability, and waiting for ring space under any mode. The committer therefore holds a **pin
on the memtable** across the append — holding the memtable is what holds the log open. Any change
that shortens that pin risks operating on a freed block manager.
:::

## Where an append stops waiting

A committer stages its record into the log's ring and one flush thread writes whatever completed as
one contiguous run. Where the committer stops waiting is the sync mode's only real difference.

Under `TDB_SYNC_INTERVAL` and `TDB_SYNC_FULL` it waits for the flush thread to carry the durability
frontier past its record, so an acknowledged commit has left the process. Under `TDB_SYNC_NONE` it
returns as soon as the record is staged, which is what that mode promises and what makes it the
weakest rung of the ladder in [Durability](/concepts/durability).

Staging cannot outrun the writer without bound, because reserving ring space still blocks when the
slot being claimed holds bytes the flush thread has not written.

That block is a wall: it stops every committer at once, for as long as the flush thread needs to
free the slot. So the append path paces **before** reaching it. Once the ring is seven eighths full
of unwritten bytes, a committer dwells briefly, rising with the fill toward a small cap, and ingest
meets the writer's rate gradually instead of colliding with it.

The pacing is the same backpressure policy the immutable queue uses, given the ring's fill as
another pressure input, so there is one place that decides how hard to push back rather than two.
It is applied on the append path rather than at admission because the append already holds the log
pinned — reading the lag there is two atomic loads and no extra pin, where admission would have to
pin the active memtable on every commit just to look.

Measured on a sixteen-family churn workload, pacing cut commits that stalled past forty milliseconds
by roughly three quarters and halved p99.9, at the cost of about a hundred microseconds at p99 —
the dwell itself, paid by the commits that would otherwise have hit the wall.

:::caution[A clean close is what makes the weakest mode safe]
Nothing waits for a staged record under `TDB_SYNC_NONE`, so the only thing that guarantees it
reaches disk on an orderly shutdown is that closing a block manager joins its flush thread and
drains the ring before touching the descriptor. Break that and the mode loses data on a clean
close, silently, which no crash test would catch.
:::

## The rotation lock is on the commit path

Rotation runs on whichever committing thread finds the memtable full. The others do not queue behind
it. A rotation has to happen, but it is not work any particular caller must do, and the write that
prompted it has already landed, so a committer that finds the lock held goes back to its commit and
leaves the rotation to the thread already doing it. Declining rather than waiting is what keeps a
mutex that hands off by barging from starving one committer for as long as the rest keep arriving.

The lock is still unlike any other in the engine. Time spent holding it is time no other committer
can rotate, so a memtable that is already full stays full for the length of the hold.

The rotation itself is meant to be short — a slot swap and little else, with the next log opened
ahead of time so no file creation happens under the lock. It is not always: when the prepared log is
not ready the rotation opens its own, and on a slow or virtualised filesystem that open dominates
everything else the rotation does. What is not safe is anything else borrowing the lock for
convenience, or the rotation itself blocking while it holds it.

:::caution[Never hold the rotation lock across a wait or a device barrier]
Anything that sleeps, polls, or issues an `fsync` while holding it stops every committer in the
database for the whole of it, and the result is multi-hundred-millisecond commits that no amount of
subsystem-level tuning explains — the cost lands on threads that had nothing to do with the work
being done.

The rule is kept in the simplest way available: **nothing outside the rotation itself takes the
lock.** The only two acquisitions in the engine are `engine_maybe_rotate` and
`engine_force_rotate`.

That half of the rule only covers other callers. The rotation's own work has to obey it too, and the
one place that failed was the fullness re-check: having taken the lock, it asked whether the memtable
was still full, and measuring a memtable takes its pin and its range tombstone lock, both of which
wait. So a rotation could sit on the lock indefinitely without doing anything slow itself. It now
compares a rotation marker taken before the lock instead — the marker moves whenever the
reader-visible set does, which answers "did someone else rotate while I waited?" without touching
either lock. The paths that would otherwise be tempted avoid it by construction — the
value-log reclaim runs under the column-family registry read lock alone, and the interval sync
ticker reaches the log through the same pin an append takes rather than through the lock, so its
`fsync` blocks nobody's commit but its own.
:::

The rule this leaves has two halves.

**If you need the active log not to swap under you, pin the memtable — do not take the lock.**
`tidesdb_l0_sync_active_wal` is that pattern: the same pin an append takes, safe because a flush
drains the writers epoch before it closes a log.

**If you need files not to move under you, claim rather than freeze.** Backup and clone copy the
whole database and a family's sstables respectively, and holding the lock across either would be
the longest hold in the engine. Neither needs it. A copy only requires that nothing *removes* a
file it is about to read, and both paths work from a snapshot taken up front: backup copies the
length its own commit left behind, and clone copies each sstable to the length the manifest
recorded. A flush landing a new file meanwhile is not in either snapshot, which is what a
point-in-time copy means.

What removes files is compaction and value-log reclaim, and both are claimed with an atomic flag
rather than locked out — the same claim the compaction scheduler already used. Backup takes the
value-log claim too, because a reclaim moves live values from one segment into another and unlinks
the source, which can strand values a copy has already passed.

## Waiting for a flush

A synchronous flush rotates and then waits for the **immutable queue to drain** — not merely for the
generation it just sealed to reach L1.

That distinction is the whole point, and getting it wrong caused a data-loss bug. Waiting on the
sealed generation alone looks better: under sustained writes the queue may never be observed empty,
so a queue wait can report contention long after the caller's own data has landed. But the callers
that matter here — [backup](/reference/maintenance#tidesdb_backup) and
[clone](/reference/column-family#tidesdb_clone_column_family) — **copy files**. Everything they
should capture has to be in a file before they start.

And a rotation seals nothing at all when the active memtable is empty, which is an ordinary state.
A flush that waited only on what it sealed would then return immediately while generations from
earlier rotations were still queued and still only in memory, and the copy would quietly miss their
data. It is not a rare interleaving; it needs nothing to fail.

:::caution[Draining the queue is the contract, not an implementation detail]
The cost is real: a database under sustained writes may never show an empty queue, so this call can
report `TDB_ERR_LOCKED` when the caller's own data has in fact landed. That is the safe direction to
be wrong in. Narrowing the wait to the caller's own generation trades a spurious busy result for a
silently incomplete copy, which is not a trade this engine makes.
:::

## Backpressure

Ingest can outrun flush. Left alone, the queue of sealed memtables grows without bound, and
memory with it, until the process dies of success.

It can also outrun **merging**, and the two fail independently. A burst can drain out of memory
promptly — an empty queue, flush entirely keeping up — and still leave a flush tier of runs behind
that every later read has to merge across. Pacing on the queue alone cannot see that: it measures
whether the memtables are being written out, not whether what was written is being merged down. So
admission weighs both, and an empty queue is a free admit only while the tier is also shallow.

Admission is consulted once per distinct column family a commit touches, and reads the queue
depth against the configured limit:

| Depth | Decision |
| --- | --- |
| Below three quarters of the limit | **Admit** — proceed now |
| Between three quarters and the limit | **Throttle** — dwell, then proceed |
| At the limit | **Block** — wait for the queue to drain, then re-evaluate |

The throttle dwell rises with depth — a per-slot step for each slot filled past the
high-water mark — so pressure is applied gradually rather than as a cliff at the limit.

The flush tier has its own band beside the queue's, on the same three outcomes: below the slow mark
a deep tier costs a writer nothing, past it the dwell grows with the depth, and at the stall mark the
writer waits for the tier to drain. The compaction trigger sits below both, so merging is already
underway before ingestion is slowed and well underway before it is stopped. Whichever band asks for
more wins, so neither pressure is masked by the other.

Blocking has a **ceiling**. A writer held too long is admitted regardless, and the event is
counted as `write_stall_ceiling_hits`. This is a deliberate choice about failure modes: a
flush that has stopped draining is a broken database, and blocking every writer forever turns
a recoverable problem into an unrecoverable one. Admitting past the ceiling keeps the database
slow rather than stuck, and makes the condition observable instead of silent.

## Reclamation

A sealed memtable can be freed once its data is durable in L1 and no reader is inside it.
The second half is the hard part, because readers take no locks.

Two mechanisms cover the two ways a memtable is reached:

- The **active slot** is guarded by a reader epoch. A reader enters the epoch, loads the
  pointer, and exits when done. A rotation that replaces the slot waits for the epoch to
  drain before the old memtable can be retired.
- A **queued** memtable is reference counted. A reader takes a reference for as long as it is
  inside; reclamation waits for the count to fall back to its structural baseline.

`claimed` prevents two flush workers from taking the same memtable, and `flushed` records that
its data reached L1 — only then may the log be unlinked, because until that moment the log is
the only durable copy.

### Reclaiming a sealed memtable

"Waits for the readers to drain" is where a flush would hurt the rest of the database if it were
taken literally.

A flush retires the memtable it just installed while holding the column-family registry read lock,
and it holds that lock across the whole install because the level sets it mutates belong to
families the lock keeps alive. Creating or dropping a family takes the same lock for writing. So a
retire that waited for a reader to leave would hold a read lock for as long as that reader stayed.
The announcement holds off readers that have not arrived yet. It does nothing about a reader already
inside, and the writer waits for every one of those. A `tidesdb_create_column_family` then takes as
long as the reader the flush is waiting on.

The reclaim is therefore bounded. It rechecks whether the readers have gone a fixed number of
times, and if they have not, it puts the memtable on a **pending list** and returns. The
deferred-free reaper sweeps that list each second, freeing whatever has since drained. Nothing is
leaked — a memtable still pinned at close is freed when the L0 is destroyed — and the flush gives
the registry lock back on a bound that does not depend on how long some reader chooses to stay.

The overwhelmingly common case still frees inline: a reader that entered just before the retire is
normally gone within a recheck or two, and the deferral is what happens when it is not.

### Rotating on idle

A rotation normally runs on the committing thread that filled the memtable, which means a database
that stops taking writes never rotates again. The data is not at risk — its log is durable — but
nothing else improves either: the log cannot be unlinked until the data reaches L1, so recovery
stays long, reads keep paying for a memtable they could be reading from an sstable, and compaction
never sees the shape it would act on.

So a ticker rotates an active memtable that has gone a whole `memtable_idle_flush_seconds` without a
write. The idle signal is the memtable's size sampled across two ticks: unchanged and non-zero means
nothing landed in between. That keeps the cost off the write path entirely — no timestamp stamped
per commit, no counter to contend on. Two different writes could in principle leave the size
identical, and the cost of being wrong is a rotation one interval early, which is legal at any time.

It is opt-out rather than opt-in, because a database that never drains is the more surprising
behaviour. Setting the interval to zero turns it off, which is what a laptop or a metered volume
wants — rotating on idle is a write a quiet process would not otherwise make.

## Recovery

On open, every `NNNNNNN.log` still present is replayed in generation order. Each becomes a
sealed memtable in the queue, and a fresh active memtable is installed above them, so the
recovered state has exactly the shape a running database has. The recovered generations are
then flushed normally.

Replay walks a log by reading framed blocks forward until one cannot be read. A torn final
record — a crash mid-append — ends the replay there, which is correct: that record was never
acknowledged.

:::caution[The log must have no holes]
Because replay stops at the first unreadable block, a **gap** in the middle of a log does not
skip one record — it silently discards every record after it. The append path guarantees no
gap can exist by only ever writing the contiguous completed run; see
[Block manager](/internals/block-manager). This is the single most consequential invariant in
the write path.
:::

Records carry their own sequence, so replay applies each at the sequence it committed with
rather than at its position in the file. After replay the clock is reseeded past the highest
sequence anything durable holds, so no sequence is ever reissued.

Not every durable batch is applied. A commit whose batch reached the log but failed to enter the
memtable appends an abort record naming its sequence, and replay gathers those first so a batch can
be cancelled by a record written after it. Without that, the record's mere presence would bring
back a transaction its caller was told had failed.

A `PREPARE` record with no matching `COMMIT` or `ROLLBACK` after it is staged as in-doubt
rather than applied, and surfaces through
[`tidesdb_recover_prepared`](/reference/transaction#tidesdb_recover_prepared).

## Invariants

| Invariant | Why |
| --- | --- |
| Enqueue before swapping the active slot | Otherwise a reader sees neither copy and reports a live key absent |
| A pinned memtable keeps its log alive | Rotation does not drain the ring; a committer may still be waiting on that file |
| A log is unlinked only after `flushed` | Until L1 has the data, the log is the only durable copy |
| A log that will never be written to is unlinked, not just closed | An abandoned log is scanned, replayed and given a memtable on every subsequent open |
| Logs are replayed in generation order | Ordering comes from the file name; nothing else records it |
| An idle non-empty memtable is rotated on a timer | Otherwise a database that stops taking writes holds its last writes in memory for the life of the process, keeping its log unreclaimable and its data out of reach of compaction |
| A memtable is freed only after readers drain | Epoch for the active slot, refcount for queued ones |
| A flush retains a key's chain against the reclamation floor, not just its newest version | The floor is what a frozen snapshot rests on. Taking only the newest drops the versions under it whatever the floor says, and a repeatable-read reader below an overwrite then finds a live key absent |
| A flush never drops a base tombstone | Its output lands in L1, the shallowest tier, where a tombstone is what shadows older versions in the levels beneath it |
| A memtable takes its value log floor when it becomes active, not at its first reference | A value reaches the value log before the commit that produced it reaches any memtable, so a floor taken later leaves a window where a reclaim drops the segment it just landed in |
| A memtable lowers that floor onto a reference's own segment | Its floor covers what was written after it became active; a value separated a moment before a rotation is applied here while living below that point |
| The floor is released only when the flush installs | Until an sstable names those values, this memtable is the only thing that does |
| A flush never waits out a reader to free a memtable | It holds the registry read lock, so an unbounded wait there blocks family create and drop for exactly that long; it defers to the reaper instead |
| Blocking on backpressure has a ceiling | A stuck flush must degrade to slow, not to deadlocked |
| Ingestion is paced against merging, not only against flush | They fail independently: an empty queue with a deep tier means flush kept up and merging did not, and every later read pays for it |
| A synchronous flush waits for the immutable queue to drain, not for its own generation | Backup and clone copy files, and a rotation seals nothing when the active memtable is empty — so waiting on the sealed generation returns while earlier generations are still only in memory, and the copy misses them |
