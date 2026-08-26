---
title: Transactions and MVCC
description: The sequence clock, snapshots, the commit-status ring, first-committer-wins reservations, and two-phase commit.
slug: internals/transactions-and-mvcc
part: internals
sidebar:
  order: 13
---

# Transactions and MVCC

## The problem

Readers must not block writers and writers must not block readers, while each reader still sees
a coherent view of the database. The standard answer is multi-version concurrency control: never
overwrite, always append a new version, and let each reader decide which versions it may see.

That turns concurrency control into a question about **numbers**. Every write gets a sequence;
every reader gets a ceiling; a version is visible if its sequence is at or below the ceiling.
No locks are involved in a read.

The engine's MVCC core is deliberately pure — it knows sequence numbers and precomputed key
hashes, not engine structures — so it builds and tests standalone.

## The clock

Three things live in the clock:

**A monotonic counter.** Every commit draws a sequence from it. Sequences are never reused; the
counter only moves forward, including across restarts (see [Recovery](/internals/recovery)).

**A commit-status ring.** Drawing a sequence and completing a commit are not the same instant,
so a sequence that has been drawn but not finished must be invisible — otherwise a reader could
see half a batch. The ring records, for the most recent sequences, whether each one committed.

The ring is bounded, and what happens past its edge is the interesting part. A sequence older
than the ring is **treated as committed**, because it must be: it was drawn long enough ago that
it cannot still be in flight, and it either applied or was abandoned. That eviction rule is what
keeps the visibility check O(1) and the memory fixed, rather than tracking every sequence ever
issued.

**A reservation table** for conflict detection, described below.

## Snapshots

A snapshot is a sequence ceiling, and the isolation level decides what it is:

| Level | Ceiling |
| --- | --- |
| Read uncommitted | Unbounded — even in-progress sequences are visible |
| Read committed | The current sequence, re-read for each operation |
| Repeatable read, snapshot, serializable | Frozen when the transaction begins |

Freezing at begin is what makes repeated reads stable: the ceiling does not move, so a version
that committed after the transaction started is invisible no matter how many times it looks.

The ceiling is not quite the only filter. A commit whose batch reached the log but failed to enter
the memtable leaves entries behind at a sequence that never committed, and those are stepped over
in favour of an older visible version at **every** level — including read uncommitted, whose
unbounded ceiling would otherwise return them. "Uncommitted" means a sequence still in flight, not
one that was given up on.

A snapshot costs nothing to take — it is a number — but holding one is not free. The oldest live
snapshot is the floor below which [compaction](/internals/compaction) may drop old versions and
tombstones. A transaction left open holds that floor down and keeps garbage alive, which surfaces
as `min_snapshot_seq` in the database statistics and as space that will not reclaim.

## Named snapshots

A transaction's snapshot is a number it draws at begin and drops when it ends. A **named snapshot**
is the same number held deliberately: `tidesdb_snapshot_create` captures the current sequence and
keeps it, and a transaction opened against it reads as of that point.

The mechanism is already everywhere. Every read resolves at a ceiling, and the memtable and the
btree both take the newest version at or below one, so reading the past needs no new path — only a
way to say which ceiling. What the handle adds is the **retention**.

A snapshot is registered exactly as a repeatable-read transaction is, so it appears in the minimum
the registry publishes and holds the reclamation floor at its own sequence. That is what keeps the
versions it resolves to alive: compaction may not discard above the floor, and a flush carries a
key's chain into L1 on the same rule.

:::caution[The ceiling is free; the retention is the whole feature]
Setting an older ceiling is a few lines. Below the floor a merge keeps one version of a key — the
newest at or below it — and drops the rest, so a read at an older ceiling finds nothing there and
reports a key that existed as **absent**. Available and untrue.

So a sequence is readable exactly while something has been holding the floor under it, and the
engine tracks where that line is rather than leaving a caller to guess. The **oldest readable
sequence** is the highest floor any collection has ever taken: at or above it nothing was ever
eligible for collection, and below it the state is gone. `tidesdb_txn_begin_at_seq` compares against
that and returns `TDB_ERR_TOO_OLD` instead of answering from what survived.

The watermark is raised where a floor is *taken*, not where the collection finishes. A merge that
has already read a floor and is still running has to be visible to a reader deciding whether its
sequence is safe, or the check would pass a moment before the versions disappeared.

The transaction registers before the check, in the same order and for the same reason: joining at
that sequence caps the floor every later collection takes, so the watermark cannot move above it
once it has been read.

A reopened database cannot account for what an earlier run collected — nothing records it, and the
sstables hold only whatever survived — so the watermark starts at the sequence recovery resumed
from, and points from before a restart are refused.
:::

A snapshot is the stronger of the two. It holds the floor from the moment it is taken, so the point
stays readable; a bare sequence is readable only while something else happens to be holding the
floor under it, and on an idle database the next merge takes that away.

The cost is the cost of a long-running transaction, because it is the same mechanism: a snapshot
left open pins `min_snapshot_seq` and the space below it will not reclaim. It shows up in exactly
the place a leaked transaction does, and is diagnosed the same way.

One thing a snapshot does not restore. Expiry is judged against the published clock at the moment
of the read, not against the snapshot's sequence, so an entry whose lifetime has elapsed reads as a
tombstone through a snapshot taken while it was live. A snapshot travels over versions, not over
deadlines.

## Reservations: first-committer-wins

At snapshot and serializable isolation, a commit must not silently overwrite a write it did not
see. The check is a reservation over the transaction's write set.

Each key hashes into a slot in a fixed table. A slot packs two things:

```
  [ 16-bit key fingerprint ][ 48-bit claiming commit sequence ]
```

The fingerprint is what lets the check stay local on a fixed-size table. Two different keys can
land in the same slot; without a fingerprint the commit could not tell a genuine same-key conflict
from a hash collision, and would have to read another committer's applied version to disambiguate.
With it, **the slot alone answers the question** — no reaching into anyone else's data.

:::note[The bound the fingerprint is checked against is a cached minimum]
The fingerprint only decides the outcome for an occupant no newer than the oldest open snapshot; a
newer one is treated as a conflict whatever its fingerprint says, because a concurrent writer of the
colliding key could still depend on the slot.

Computing that minimum exactly means scanning every registry shard, and a reservation runs once per
written key, so the commit path does not compute it. The registry publishes the value instead,
refreshed on the compaction scheduler's tick, and the commit path reads it as a single relaxed load
hoisted once for the whole write set. A stale reading is only ever *low*, which is the conservative
direction: it makes more occupants count as newer, so it can reject a commit that would have been
admitted, and can never admit one that should have been rejected.

The empty registry is the case that needs care. The scan answers `UINT64_MAX`, a sentinel meaning
nothing constrains you rather than a real minimum, and publishing it would let a transaction
beginning afterwards hold a snapshot *below* the published value -- the one direction a reader of
this may not tolerate. The publisher stores zero for an empty set instead.
:::

The subtlety is what each key is validated *against*. Not the transaction's snapshot, but **the
version this transaction actually read for that key**, recorded when
[`tidesdb_txn_get`](/reference/transaction#tidesdb_txn_get) was called. A blind write with no prior
read falls back to the snapshot.

This is why the API distinguishes tracking and non-tracking reads. A read that feeds a write must
be tracked, so the write is validated against what it was based on. A probe whose answer does not
determine what is written should be untracked, because widening the footprint only creates
conflicts that are not real.

Losing a reservation is `TDB_ERR_CONFLICT`, raised before anything durable has been written.

### An interval has no key to hash

A [range delete](/reference/transaction#tidesdb_txn_delete_range) writes an interval, not a key, so
there is no hash for it to claim and no fingerprint that could describe it. Two transactions — one
deleting a range, one writing a key inside it — can never collide in the table above, however they
are ordered.

Two things close that, and they cover different windows.

**A second, small table holds the intervals themselves.** A batch writing one claims it before
reserving any of its keys, and every point write checks that table before taking its own slot. The
table is almost always empty, so the check is one relaxed load; only when a range delete is actually
in flight does a write compare its key against a handful of bounds. That is also what carries a
**two-phase** range delete through the window between its prepare and its commit.

The interval goes back **once the batch is visible, and not before**. A key reservation is renamed
rather than dropped, because the slot itself is what a later writer of that key reads; an interval
has no slot of its own to read, so what replaces it is the committed delete, which a later writer's
conflict scan finds. Releasing earlier leaves the gap between the two uncovered, and not releasing
at all spends the table: it has a fixed number of slots, so one leaked per commit ends with every
later range delete in the database refused as a conflict that no retry could clear.

The slots are a fixed width, which is where the public
[`TDB_MAX_RANGE_BOUND_SIZE`](/reference/transaction#tidesdb_txn_delete_range) limit on a range
delete's bounds comes from. A longer bound is turned away at the API rather than narrowed to fit,
since a narrowed bound describes a wider range than the caller asked for.

**A commit gate covers the rest.** The interval table alone still leaves the reverse order open: a
point write that has already reserved, and is not yet visible, cannot be seen by a range delete's
conflict scan. So a commit carrying one takes the database's commit gate exclusively and runs alone,
while every other commit at snapshot or above holds it shared and never waits on another. The gate
is held for the whole commit rather than just the reservation, because a batch that has reserved but
not yet marked its sequence visible is exactly the write the delete must not miss.

A two-phase transaction takes the gate only for its **prepare**. The in-doubt window that follows
has no bound, and holding it there would stall every other committer for as long as the transaction
stayed undecided — the held interval covers that window instead.

## The conflict scan, and what it does not read

The reservation catches a transaction that is committing *right now*. It cannot catch one that
committed and finished between this transaction's snapshot and its commit — that writer has already
released its slot. So a commit at snapshot isolation or above also scans its write set against the
data itself, and repeatable-read and serializable scan the read set the same way.

The question that scan asks is narrow. Not *what is the newest version of this key*, but only
**does any version of it exist above my snapshot**. That distinction is worth a great deal, because
answering the first question means descending a btree in every overlapping sstable at every level,
parsing nodes and verifying checksums, purely to discard the answer.

Every sstable records the newest sequence it contains in its footer. An sstable whose newest
sequence is at or below the transaction's snapshot **cannot** hold a conflicting version, so the
scan skips it on that field alone — no descent, no node read, no checksum. Skipping it stays correct
even when that sstable does hold the key, because the only thing being asked is whether something
newer exists, and a skipped sstable's answer is no.

Since flush and compaction continuously produce sstables while transactions are short, nearly every
sstable predates any live transaction's snapshot, and nearly the whole scan resolves from metadata.

:::note[The memtable is still read]
The skip applies to sstables, which carry the sequence range in their footer. A conflicting commit
has usually not been flushed yet, so the memtable genuinely has to be consulted and is the part of
the scan that remains.
:::

A [range delete](/reference/transaction#tidesdb_txn_delete_range) asks the same question over an
interval rather than a key: *does any key in these bounds sit above my snapshot*. It prunes on the
same footer field — a table whose newest sequence is at or below the snapshot holds nothing newer
wherever its keys fall — and stops at the first key it finds, since one is all the commit needs to
know.

Two things differ from the point form. Every source is asked rather than the first one holding the
key, because a newer key in an interval can be in any of them and a shallower source says nothing
about what a deeper one holds elsewhere in the range. And there is **no fallback**: a source that
cannot answer an interval reports busy, which the commit retries, rather than being stood in for by
a full read the way a missing point probe is. A missing implementation must never read as a clear
run.

Busy has to mean *transient*, though. The retry is bounded, and a source that answers busy for a
reason that will hold every time — a bound too long for a buffer, say — turns a permanent condition
into `TDB_ERR_IO` after the retries run out. A condition the caller cannot clear belongs at the API,
as an argument error, not on this path.

## The write and read sets

The **write set** buffers operations in insertion order. Order is what makes savepoints work: a
savepoint is a position in the sequence, rolling back to it discards the tail, and releasing it
forgets the mark without discarding anything.

The **read set** records what tracking reads observed — key and version — and exists only to feed
the reservation check at commit.

Both are per-transaction and single-threaded, which is why a transaction handle is not
thread-safe. The one exception is the flag
[`tidesdb_txn_request_abort`](/reference/transaction#tidesdb_txn_request_abort) sets: it is the only
field another thread ever writes, and it changes nothing else, so the thread that owns the
transaction is still the only one that moves its state.

## The registry

Live transactions are registered so the engine can compute the oldest live snapshot. The registry
is on the commit path, so its cost matters: each transaction holds its own slot and leaves in
constant time rather than by scanning a list.

It is also **sharded**, because joining and leaving are per-transaction rather than per unit of
work — every transaction does both exactly once, whatever else it does — so a single lock made
this a database-wide serialization point that got worse with concurrency, not with load.

A transaction takes the shard of the **thread that joins it**, claimed once per thread from a
counter. The thread is what actually contends, so it is what the shards have to spread. Deriving
the shard from the transaction's own address instead looks equivalent and is not: a caller running
one short transaction at a time — a statement-scoped transaction under autocommit, say — frees and
reallocates at the same few addresses, so the shards collapse onto a handful of slots and unrelated
threads queue on one lock. Measured on sixteen threads that difference is most of the throughput.

The transaction stores the slot it landed in rather than recomputing it, so a leave can never
disagree with its add about which lock it needs — which is also what lets a transaction be freed on
a thread other than the one that began it.

:::note[The shard count is bounded by the walk, not by the core count]
More shards spread the join and leave further, but the enumeration below holds **every** shard for
its whole walk, so a serializable commit acquires that many locks at once. Past about sixty a
thread holds more locks than tooling will model — ThreadSanitizer caps a thread there and aborts —
and it is a lot of lock traffic for one commit regardless. The count is chosen against that bound
rather than against the number of cores.
:::

The two readers of the set treat the sharding differently, and deliberately:

- **The oldest live snapshot** takes one shard at a time. The answer can come out too low but
  never too high, and too low is the safe direction for a reclamation floor — it keeps a version
  some reader might still want. It cannot come out too high, because a transaction registering
  after its shard was read draws its snapshot from a monotonic clock and so is above the minimum
  already, and one that leaves only raises the true minimum above what was reported.
- **Serializable validation** holds every shard for the whole walk, so it decides against one
  instant of the live set rather than a smear across shards. A peer appearing between two shards
  could otherwise be missed by this validation and by its own. The shards are taken in index
  order, the only order anything takes them in, so the walks cannot deadlock against each other.
  Holding all of them is affordable precisely because this walk is rare — a serializable commit
  or a statistics call, never the ordinary write path, which touches one shard.

## Timeouts

A transaction that is begun and never resolved is not merely idle. It holds its snapshot, and at
snapshot and serializable isolation its write reservations, so the reclamation floor cannot rise
past it -- compaction may not drop the versions below that floor, and the value log may not reclaim
their bytes. A leaked transaction therefore costs disk for as long as the database is open, and
nothing else in the engine can decide it is safe to let go of.

A timeout bounds that. It is off by default (`txn_timeout_seconds` is 0), applies to every
transaction when set, and a single transaction overrides it through `tidesdb_txn_set_timeout`.

Two properties are worth knowing:

- **Expiry is lazy.** No background thread aborts anything. The next operation on the transaction
  notices its deadline has passed, aborts it there, and returns `TDB_ERR_TXN_EXPIRED`. A
  transaction that is never touched again is never expired -- it is resolved at close instead.
- **The clock is cached, not read per check.** A ticker publishes the current second, and a check
  is one relaxed load against it. That is what keeps a transaction with no timeout paying nothing,
  and it also means a deadline is accurate to about a second rather than exactly.

## Two-phase commit

Ordinary commit decides and applies in one step. Two-phase commit splits the decision from the
application so an external coordinator can gather votes from several participants first.

**Phase one — prepare.** Runs the same conflict checks as commit and durably logs the write batch
under a caller-supplied transaction id, but leaves the writes invisible and unapplied. The
transaction holds its snapshot and its reservations until it is resolved — so an undecided
prepared transaction applies backpressure to anything contending for its keys, and holds the
`min_snapshot_seq` floor down. Deciding promptly is not optional in a busy system.

A read-only transaction prepares with nothing durable and needs no phase two.

A prepared batch that separated any of its values is also the only thing naming them. Its entries
are in no memtable and no sstable until phase two decides it, so the
[value log](/internals/value-log) counts a staged batch's references alongside the installed tables
and holds a floor over their segments — the same reason its write-ahead log generation is pinned,
applied to the other store.

**Phase two — commit or roll back.** Durably logs the decision, then applies the batch and makes
it visible.

The critical detail is the sequence. Phase two draws a **fresh** sequence at decision time and
carries the batch inside the commit record, rather than applying at the sequence the prepare
held.

:::caution[Why phase two must re-sequence]
Between a prepare and its decision, other transactions commit. If the prepared batch applied at
its original — now older — sequence, a key written in that window would shadow it, even though the
prepared transaction decided later. Re-sequencing at decision time makes replay and live
application agree: the batch lands where it was decided, not where it voted.
:::

Re-sequencing decides what happens to the reservations. The prepare claimed a slot for every key
it wrote, each naming the sequence it drew then — and that sequence is superseded, so it is never
marked committed. Phase two therefore **hands each slot over** to the sequence that committed,
once the batch is durable and applied.

A slot left naming the superseded sequence would read, to every later writer of that key, as a
committer still in flight: they would lose a conflict to a transaction that had already finished,
and go on losing it until the ring aged the sequence out — permanently on a quiet database, and
not at all on a busy one.

The hold is renamed rather than dropped and retaken. Releasing it would leave the slot empty, and
a writer whose snapshot predates the commit would then claim it freely and overwrite the batch
with no conflict raised — the precise failure the reservation exists to prevent. Renaming keeps
the hold unbroken and leaves the slot naming a sequence that later comparisons can be made
against.

The hand-over waits for the batch to be durable because a failed append leaves the transaction
prepared for a retry that draws a different sequence, and the slots must still name the prepare's
for that retry to find them.

A transient I/O failure in phase two leaves the transaction **prepared**, not aborted, so the
coordinator can retry the same decision. Anything else would let a participant unilaterally
abandon a transaction the coordinator had already committed elsewhere.

### What an undecided prepare keeps alive

A prepared batch never enters a memtable, so it is durable only in the log its PREPARE record was
written to. That generation's log therefore cannot be unlinked when it flushes, the way an ordinary
generation's is once its data reaches L1 — the flush moved no part of that batch anywhere.

**It is that one generation, and no other.** The pin is keyed on the generation the record lives in,
not on whether some prepare somewhere is undecided. The difference is not academic: an engine driven
by a coordinator that always has a transaction in flight — which is what MariaDB's internal
two-phase commit between the engine and the binary log looks like under concurrent load — would
otherwise keep *every* log it ever wrote, since the count is never zero at the moment a flush asks.
The store then grows without bound in a way that looks like a compaction failure and is not one.

Once phase two decides, the prepared generation is free immediately, and its log goes. That follows
from the commit record carrying the whole write set: replay applies it inline, so nothing needs the
original PREPARE any more. A rollback leaves nothing to undo, so the same holds.

The pin is taken by recovery itself, not by whoever adopts the transaction. A database that reopens
with a batch in doubt and simply carries on writing — never asking for its in-doubt list — must
still keep that log, because it holds the only copy of a batch someone may yet decide.

## Invariants

| Invariant | Why |
| --- | --- |
| A sequence is never reused, across restarts included | Reuse would make two different writes indistinguishable |
| A drawn but uncommitted sequence is invisible | Otherwise a reader sees half a batch |
| Sequences past the ring's edge count as committed | They cannot still be in flight; this bounds the ring |
| A write is validated against the version actually read | Validating against the snapshot alone misses read-modify-write races |
| The reservation slot carries a key fingerprint | Distinguishes a real conflict from a hash collision without reading others' data |
| Compaction may not drop above `min_snapshot_seq` | A live snapshot must still see what it could see |
| A flush retains against that floor too, not only a merge | A memtable holds the whole chain, so a flush that took the newest version alone would drop what the floor was protecting and a frozen reader would find a live key absent |
| A named snapshot is registered, not just remembered | The floor is the minimum the registry holds; a sequence kept outside it protects nothing, and reading there answers from whatever a merge happened to leave |
| Phase two draws a fresh sequence | The batch must land where decided, not where it voted |
| A decided prepare's reservations move to the sequence that committed | The sequence the prepare reserved with is superseded and never marked committed, so a slot left naming it reads as a committer still in flight and refuses every later writer of that key |
| A failed phase two leaves the transaction prepared | A participant must not abandon a decision unilaterally |
| An undecided prepare pins its own log generation, and only that one | Its PREPARE record is the only copy of the batch. Pinning on a database-wide count instead keeps every log ever written whenever a coordinator always has one in flight |
| A decided prepare frees its generation at once | The commit record carries the write set and replay applies it inline, so nothing needs the original PREPARE |
| Recovery takes the pin, not the caller who adopts the batch | A database that reopens and never asks for its in-doubt list must still keep the only copy of one |
