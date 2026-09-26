---
title: Transactions and MVCC
description: The sequence clock, snapshots, the commit-status ring, the in-flight claim set, and two-phase commit.
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

Four things live in the clock:

**A monotonic counter.** Every commit draws a sequence from it. Sequences are never reused; the
counter only moves forward, including across restarts (see [Recovery](/internals/recovery)).

**A commit-status ring.** Drawing a sequence and completing a commit are not the same instant,
so a sequence that has been drawn but not finished must be invisible — otherwise a reader could
see half a batch. The ring records, for the most recent sequences, whether each one is in
progress, committed, or aborted, each slot tagged with the sequence it describes so a slot reused
by a later sequence never reads as a decision about an earlier one.

**A watermark.** Readers do not consult the ring. What they take their ceiling from is the
**watermark**: the highest sequence below which every drawn sequence has been decided, committed
or aborted. Every commit ends by deciding its sequence and carrying the watermark forward over
every decided sequence above it, and every failure path after the draw decides the sequence as
aborted for the same reason. A sequence is committed only after its batch is applied in full, so
everything at or below the watermark is whole and final, and a ceiling taken from it never admits
a version that could still change or disappear.

A commit does not return until the watermark has passed its own sequence. The wait is on the
commits in flight below it, each inside its own commit window, and it is what makes a commit's
writes visible to the caller's very next transaction — the watermark publishes in order, and
"returned" means "published".

The ring is bounded, and the bound is enforced rather than assumed: the clock will not draw a
sequence a ring's width above the watermark, so a slot the watermark has yet to read is never
recycled underneath it, and a slot always describes the sequence it is asked about. Nothing reads
the ring below the watermark — a reader's question is answered by the watermark alone — so there is
no rule for sequences that have aged out of it.

The sequence a two-phase transaction drew at its prepare is spent the moment its record is durable:
phase two commits at a fresh one, so no version ever carries it, and it is decided as aborted so the
watermark passes it. What holds the batch's keys through the in-doubt window is not the ring but the
claim set — see [Two-phase commit](#two-phase-commit).

**An in-flight claim set** for conflict detection, described below.

## Snapshots

A snapshot is a sequence ceiling, and the isolation level decides what it is:

| Level | Ceiling |
| --- | --- |
| Read uncommitted | Unbounded — even in-progress sequences are visible |
| Read committed | The watermark, re-read for each operation |
| Repeatable read, snapshot, serializable | The watermark when the transaction begins, frozen |

Freezing at begin is what makes repeated reads stable: the ceiling does not move, so a version
that committed after the transaction started is invisible no matter how many times it looks. Taking
it from the watermark rather than from the sequence counter is what makes the snapshot a
snapshot: every sequence at or below it is already decided, so nothing that was in flight when the
transaction began can land inside its view later, and no batch is ever seen half applied.

The ceiling is not quite the only filter. A commit whose batch reached the log but failed to enter
the memtable leaves entries behind at a sequence that never committed, and those are stepped over
in favour of an older visible version at **every** level — including read uncommitted, whose
unbounded ceiling would otherwise return them. "Uncommitted" means a sequence still in flight, not
one that was given up on. A flush waits for every sequence in a memtable to be decided before it
builds, so those entries are dropped there and never reach an sstable; the memtable is the only
place they can ever be, and the record of them is forgotten once the memtables that could hold
them have retired.

A snapshot costs nothing to take — it is a number — but holding one is not free. The oldest live
snapshot is the floor below which [compaction](/internals/compaction) may drop old versions and
tombstones. A transaction left open holds that floor down and keeps garbage alive, which surfaces
as `min_snapshot_seq` in the database statistics and as space that will not reclaim.

## Named snapshots

A transaction's snapshot is a number it draws at begin and drops when it ends. A **named snapshot**
is the same number held deliberately: `tidesdb_snapshot_create` captures the watermark and keeps
it, and a transaction opened against it reads as of that point.

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

## Claims: what a commit in flight holds

At repeatable read and above, a commit must not silently overwrite a write it did not see, and must
not commit on a read that a commit sequenced before it has already invalidated. Each question has
two halves: a rival that has already committed, which the data itself answers (the conflict scan
below), and a rival that is committing *right now*, which nothing in the data can answer yet. The
**in-flight claim set** answers the second.

A claim names a key — its family, its bytes and its owner, the commit holding it. The set is a hash
table of chains under striped locks, and a claim is compared by its bytes, never by its hash alone,
so two different keys in one chain are two claims, not a collision. Nothing about it is a fixed
number of slots per key: two commits of different keys never conflict on it, however wide either is,
and a commit never refuses itself. A table of hashed slots — one per key, then a run of four — did
both, and a table load of a hundred thousand rows in one transaction was refused for colliding with
its own keys.

Claims are taken **before the sequence is drawn**, in one fixed order — family, then key bytes. The
order is what makes two commits sharing keys meet at the same first key, so exactly one yields
rather than each holding half. The position is what makes validation sound: any commit whose
sequence is below mine had finished claiming before I drew, so my validation, which runs after my
draw, sees its claims. In the other order two commits could each validate against a set that did not
yet hold the other, and both go through.

What a claim meets when it joins its chain decides it:

- A **write claim** meeting another owner's write claim is refused at snapshot and serializable —
  that owner is in flight, one of the two must lose, and the later claimant does. First-committer-
  wins, decided at the claim rather than after the fact.
- At repeatable read a write claim is recorded and refuses nothing; two blind writers of one key
  both commit there. What it is for is being seen by a rival's read validation.
- A **read claim** — taken by a prepare at repeatable read or above on every key it read — is never
  refused, and refuses every later write claim on its key for as long as its owner is undecided. Why
  a prepare needs one is in [Two-phase commit](#two-phase-commit).

A claim carries its owner's sequence once drawn; until then it reads as *drawing*, and a validator
that meets one spins for the store, which is a few instructions away. Validation at repeatable read
and serializable asks the set, for every key the transaction read, whether another owner's write
claim sits **below my sequence**: that writer lands before me, my read of the key is stale at my
position, and I am refused. For every interval a scan of the transaction covered it asks the same of
every commit in flight — a write claim on a key inside it below my sequence is a phantom about to
exist — which is what the list of commits in flight is for, since an interval has no one chain to
look in. A write claim above my sequence is not my problem — that commit is sequenced after me and
validates against mine. A prepared owner's write claims read as **future**, since its final sequence
will exceed every current one, so a reader of a key it writes is serialized before the batch and not
refused, while a writer of that key at snapshot or above is.

The claims go with the commit. A refused claim drops the ones already taken, a failed commit drops
them all, and a successful one drops them once the watermark has passed its sequence, so a rival
validating against the data finds what the claims were standing in for. Nothing is renamed, aged out
or handed over.

Losing a claim is `TDB_ERR_CONFLICT`, raised before anything durable has been written.

The subtlety is what each write is validated *against*. Not the transaction's snapshot, but **the
version this transaction actually read for that key**, recorded when
[`tidesdb_txn_get`](/reference/transaction#tidesdb_txn_get) was called. A blind write with no prior
read falls back to the snapshot.

This is why the API distinguishes tracking and non-tracking reads. A read that feeds a write must
be tracked, so the write is validated against what it was based on. A probe whose answer does not
determine what is written should be untracked, because widening the footprint only creates
conflicts that are not real.

### An interval has no key to claim

A [range delete](/reference/transaction#tidesdb_txn_delete_range) writes an interval, not a key, so
there is no key for it to claim and no one chain a writer inside it could look in.

**A second, small table holds the intervals themselves**, at repeatable read and above, taken with
the claims and before the draw. A point write checks that table alongside its chain: an interval
another commit holds over its key refuses it under first-committer-wins, and is recorded beside it
at repeatable read. Under first-committer-wins the interval is checked the other way as it is taken
— entered in the table first, then compared against every commit in flight, whose claims are
complete arrays by the time the commit is on the list — so a point writer and a range delete meeting
in the same instant find each other whichever was first, and one of the two yields. An interval also
yields to another interval meeting it, and to a prepared reader holding a key inside it, which cannot
be the one to yield. At repeatable read the interval is entered and refuses nothing, exactly as a
write claim at that level is; what it is for is being met by the writers at snapshot and above and
by the readers validating under it. After the draw a range delete under first-committer-wins
validates like a write: the store for a version inside the interval above its snapshot, and the
commits in flight for a write claim inside it sequenced below it.

The table is almost always empty, so a point write's check is one relaxed load; only when a range
delete is actually in flight does a write compare its key against a handful of bounds. That is also
what carries a **two-phase** range delete through the window between its prepare and its commit.

The interval goes back **once the batch is visible, and not before** — with the batch's key claims,
and for the same reason: what replaces either is the committed write, which a later writer's
conflict scan finds. Releasing earlier leaves the gap between the two uncovered, and not releasing
at all spends the table: it has a fixed number of slots, so one leaked per commit ends with every
later range delete in the database refused as a conflict that no retry could clear.

The slots are a fixed width, which is where the public
[`TDB_MAX_RANGE_BOUND_SIZE`](/reference/transaction#tidesdb_txn_delete_range) limit on a range
delete's bounds comes from. A longer bound is turned away at the API rather than narrowed to fit,
since a narrowed bound describes a wider range than the caller asked for.

### A scan's footprint

An iterator at repeatable read or serializable keeps the interval it has covered — from the key it
sought or the first key of its range to the last key it stood on, or to the end when it ran off it,
absent keys included — and hands it to the transaction's read set when it is freed. At commit the
interval is validated like a read: the store is asked whether any version inside it sits above the
snapshot, and the commits in flight whether one sequenced below this commit writes a key inside it.
Either is a **phantom**, a row the scan would have seen had it run a moment later, and the commit is
refused. That is what makes serializable PL-3 rather than PL-3 over point reads alone: a write skew
that depends on a scan having seen no row is refused with the rest. Snapshot isolation validates no
read and keeps no footprint. An iterator whose footprint cannot be recorded fails its transaction
rather than let it commit unchecked.

## The conflict scan, and what it does not read

The claim set catches a transaction that is committing *right now*. It cannot catch one that
committed and finished between this transaction's snapshot and its commit — that writer has dropped
its claims. So a commit at snapshot isolation or above also scans its write set against the data
itself, and repeatable-read and serializable scan the read set the same way, the keys read and the
intervals scanned both.

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

The **read set** records what tracking reads observed — key and version — and the intervals the
transaction's scans covered, each at the snapshot it scanned at. It exists to feed the read
validation at commit and, at a prepare, the read claims.

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
its whole walk, so a statistics call acquires that many locks at once. Past about sixty a thread
holds more locks than tooling will model — ThreadSanitizer caps a thread there and aborts. The
count is chosen against that bound rather than against the number of cores.
:::

The two readers of the set treat the sharding differently, and deliberately:

- **The oldest live snapshot** takes one shard at a time. The answer can come out too low but
  never too high, and too low is the safe direction for a reclamation floor — it keeps a version
  some reader might still want. It cannot come out too high, because a transaction registering
  after its shard was read draws its snapshot from a monotonic clock and so is above the minimum
  already, and one that leaves only raises the true minimum above what was reported.
- **Enumeration**, which the statistics call lists live transactions with, holds every shard for
  the whole walk, so it reports one instant of the live set rather than a smear across shards. The
  shards are taken in index order, the only order anything takes them in, so two walks cannot
  deadlock against each other. Holding all of them is affordable precisely because the walk is
  rare — never the write path, which touches one shard.

## Timeouts

A transaction that is begun and never resolved is not merely idle. It holds its snapshot, so the
reclamation floor cannot rise past it -- compaction may not drop the versions below that floor, and
the value log may not reclaim their bytes. A leaked transaction therefore costs disk for as long as the database is open, and
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

**Phase one — prepare.** Takes the same claims and runs the same conflict checks as commit, and
durably logs the write batch under a caller-supplied transaction id, but leaves the writes invisible
and unapplied. The transaction keeps its claims until it is resolved — on the keys it wrote, and at
repeatable read or above on the keys it read as well — so an undecided prepared transaction applies
backpressure to anything contending for its keys, and its snapshot holds the `min_snapshot_seq`
floor down. Deciding promptly is not optional in a busy system. The sequence the prepare drew is
spent for the watermark as soon as its record is durable — no version ever carries it, since phase
two commits at a fresh one — so an undecided prepare never holds readers' ceilings down.

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

Re-sequencing is also why a prepare holds its **reads**. Its reads were validated at prepare time,
and phase two lands the batch above everything that committed while it was in doubt. A transaction
that wrote a key the prepare read, committing inside that window, would leave the batch with a
stale read at its final position — the shape every anomaly needs — and the prepared side can no
longer be the one to yield, since a participant that voted yes must be able to commit. So the
writer is refused: at repeatable read and above the prepare takes a read claim on every key it read,
and a writer of such a key is refused for as long as the batch is undecided.

Its write claims read as *future* to every validator while it is in doubt. A reader of a key it
writes is not refused — it is serialized before the batch, and its read is consistent — while a
writer of that key at snapshot or above is, first-committer-wins. The claims are dropped once phase
two has applied and marked the batch, or rolled it back. Nothing is handed over between the
prepare's sequence and the one phase two commits at, because a claim is held by presence, not by
the sequence it names.

An in-doubt batch adopted after a restart claims its keys again, and holds its intervals again, from
the entries its PREPARE record carries, and its reads again from the record written immediately
ahead of it: at repeatable read and above the prepare appends its read keys as a record of their own
under the same xid before the PREPARE, so a PREPARE that is durable always has its reads, and
recovery holds the keys for the PREPARE that follows. Read keys no PREPARE ever followed — the
prepare failed between the two appends — are dropped with the staging map. A prepared handle freed
without a decision — abandoned, which the engine allows — leaves its claims with the clock in its
place, since the record is durable and a later open may still commit it.

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

**Not its sequence.** The sequence the prepare drew is decided as spent the moment its record is
durable, and the commit-status ring may age it out like any other. What keeps the batch's keys held
is its claims, which are held by presence rather than by any sequence, so a prepare left undecided
for a ring's worth of commits refuses exactly what it refused when it was young.

## Invariants

| Invariant | Why |
| --- | --- |
| A sequence is never reused, across restarts included | Reuse would make two different writes indistinguishable |
| A drawn but undecided sequence is invisible | Every reader's ceiling is the watermark, below which every sequence is decided; otherwise a reader sees half a batch |
| Every drawn sequence is decided, committed or aborted, on every path | The watermark waits on each one; an undecided sequence would hold every later reader's ceiling down |
| A commit returns only once the watermark has passed its sequence | The caller's next transaction must see what it just committed; publication is in order |
| No sequence is drawn a ring's width above the watermark | The slot the watermark has yet to read must not be recycled underneath it |
| A write is validated against the version actually read | Validating against the snapshot alone misses read-modify-write races |
| A claim is compared by its key's bytes, never by its hash alone | Two keys in one chain are two claims; a hash collision refused a commit that had no conflict |
| Claims are taken before the sequence is drawn | A commit sequenced below mine finished claiming before I drew, so my validation sees it; the other order lets two rivals miss each other |
| A prepare at repeatable read or above holds what it read | Phase two lands it above everything that committed in doubt; a writer of a key it read committing inside that window would leave it a stale read at its final position, and the prepared side cannot yield |
| An interval is held before the draw and checked both ways | A point writer meets it in the table, and it meets the point writer in the list of commits in flight, so the two find each other whichever was first; without that a range delete and a write inside it could each validate against a set that did not yet hold the other |
| A scan's footprint is validated like a read | A key another commit put inside the interval a scan covered is a phantom, whether it is in the store above the snapshot or still a claim in flight below this commit; refusing it is what makes serializable hold over predicates and not only over the keys it read |
| Compaction may not drop above `min_snapshot_seq` | A live snapshot must still see what it could see |
| A flush retains against that floor too, not only a merge | A memtable holds the whole chain, so a flush that took the newest version alone would drop what the floor was protecting and a frozen reader would find a live key absent |
| A named snapshot is registered, not just remembered | The floor is the minimum the registry holds; a sequence kept outside it protects nothing, and reading there answers from whatever a merge happened to leave |
| Phase two draws a fresh sequence | The batch must land where decided, not where it voted |
| A prepare's claims go only with its decision | Held by presence rather than by sequence, they neither age out of the ring nor need handing over to the sequence phase two commits at; one left behind after the decision would refuse every later writer of a finished transaction's key |
| A failed phase two leaves the transaction prepared | A participant must not abandon a decision unilaterally |
| An undecided prepare pins its own log generation, and only that one | Its PREPARE record is the only copy of the batch. Pinning on a database-wide count instead keeps every log ever written whenever a coordinator always has one in flight |
| A decided prepare frees its generation at once | The commit record carries the write set and replay applies it inline, so nothing needs the original PREPARE |
| Recovery takes the pin, not the caller who adopts the batch | A database that reopens and never asks for its in-doubt list must still keep the only copy of one |
