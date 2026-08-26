---
title: Transactions and Isolation
description: Snapshots, the five isolation levels, what conflicts and what does not, and two-phase commit.
slug: concepts/transactions
part: concepts
sidebar:
  order: 2
---

# Transactions and Isolation

Every read and every write happens inside a transaction. A single put is a transaction with one
operation in it — there is no cheaper path that skips the machinery, because the machinery is
what makes the put atomic and durable.

## What a transaction gives you

**Atomicity.** Either every operation in the transaction becomes visible, or none does — across
column families as well as within one.

**A stable view.** Reads see a consistent snapshot rather than a moving target.

**Isolation you choose.** Five levels, trading strictness against the cost of enforcing it.

Writes are **buffered** until commit. Your own transaction sees its own writes immediately;
nothing else sees any of them until commit succeeds.

## Snapshots

A snapshot is a sequence ceiling: a version is visible if it committed at or below it. Taking
one costs nothing — it is a number.

Holding one is not free, though the cost is indirect. The oldest live snapshot is the floor
below which compaction may not discard old versions and tombstones. A transaction left open for
minutes prevents reclamation of everything that changed since it began, which appears as disk
usage that will not fall.

**Keep transactions short.** This is the main operational rule for using them.

## The five levels

| Level | Reads see | Can conflict |
| --- | --- | --- |
| `TDB_ISOLATION_READ_UNCOMMITTED` | Everything, including uncommitted writes | No |
| `TDB_ISOLATION_READ_COMMITTED` *(default)* | The latest committed version, re-read per operation | No |
| `TDB_ISOLATION_REPEATABLE_READ` | A snapshot frozen at begin | **Yes**, on what it read |
| `TDB_ISOLATION_SNAPSHOT` | A snapshot frozen at begin | **Yes**, on what it wrote |
| `TDB_ISOLATION_SERIALIZABLE` | A snapshot frozen at begin | **Yes**, on both |

`tidesdb_txn_begin` uses read-committed, and so does a family whose `default_isolation_level` is
left unset. **The default therefore does not detect conflicts** — see the division below, and
choose a level deliberately if a lost update would matter.

The meaningful division is the last column.

**The lower two never fail on conflict.** A commit succeeds if the I/O succeeds. A write is a
blind overwrite: if another transaction wrote the same key first, that write is simply lost. For
appending independent records — logs, events, metrics — that is exactly right, and paying for
conflict detection would be waste.

**The upper three check, but not all for the same thing**, and the difference decides which of
them you want:

- **Repeatable read** validates **what it read**. Every key it recorded a read for is checked for
  a newer committed version, which is what stops a value moving under it. It takes no reservation
  on what it writes, so two transactions blindly writing the same key still both succeed.
- **Snapshot** validates **what it wrote**, on a first-committer-wins basis. It is the level that
  stops a lost update, and it does not check reads.
- **Serializable** does both, and adds the check that catches write skew.

Whichever check fires, the loser gets `TDB_ERR_CONFLICT` at commit, before anything durable is
written.

:::caution[Conflict detection is opt-in, and ignoring it loses writes]
The default level does not check, so a race silently overwrites. Once you choose any level above
read-committed, code that ignores `TDB_ERR_CONFLICT` passes single-threaded tests and fails under
concurrency. Write the [retry loop](/getting-started#handling-conflicts) once and use it
everywhere.
:::

## Reading a point in the past

A transaction's snapshot lasts as long as the transaction. When a point in time is wanted for
longer — a consistent export, a comparison against a known-good state — name it instead:
`tidesdb_snapshot_create` captures the current sequence, and a transaction opened against that
snapshot reads as of it, point reads and scans alike.

A snapshot holds the reclamation floor for as long as it lives, which is what keeps the versions it
names readable, and is also what it costs. Treat one exactly as you would a long-running
transaction: release it when the point in time is no longer wanted, or it pins space the same way.

A sequence can also be read directly, with
[`tidesdb_txn_begin_at_seq`](/reference/transaction#tidesdb_txn_begin_at_seq). That form refuses
rather than approximates: an older point stays readable only while something holds the floor under
it, and once a merge has run past that sequence the versions it named are gone. Asking for one that
has been collected returns `TDB_ERR_TOO_OLD` instead of an answer assembled from whatever survived.
[`tidesdb_oldest_readable_seq`](/reference/transaction#tidesdb_oldest_readable_seq) says where that
boundary currently sits.

## What a write is validated against

This is the part worth understanding, because it determines which reads you should use.

This applies to the levels that validate writes — snapshot and serializable. A write is not
validated against your snapshot. It is validated against **the version you
actually read for that key** — recorded when you called `tidesdb_txn_get`. A write with no prior
read falls back to the snapshot.

So a read-modify-write is checked properly: you read version 5, someone else commits version 6,
your write is rejected because the value you based it on is stale.

The consequence is that **reads have costs beyond their own latency**. A read you record widens
what your commit must validate, so reading keys you do not base writes on produces conflicts
that are not real. Three read entry points exist for this reason:

| Call | Records the read | Use for |
| --- | --- | --- |
| `tidesdb_txn_get` | Yes | A value that determines what you write |
| `tidesdb_txn_get_notrack` | No | A probe whose answer does not feed a write |
| `tidesdb_txn_contains` | No | Existence only; allocates nothing |

A uniqueness check before an insert is the canonical `notrack` case: you care that the key is
absent, and a concurrent insert of a *different* key is irrelevant to you.

## Savepoints

A savepoint marks a position in the buffered sequence. Rolling back to it discards everything
after it and leaves the transaction active; releasing it forgets the mark without discarding
anything. They nest.

Useful for speculative work inside a larger transaction — attempt something, and if it does not
work out, unwind just that part without losing the rest.

## Two-phase commit

For transactions spanning TidesDB and something else, commit splits in two.

**Prepare** runs the full conflict check and durably logs the batch under a transaction id you
supply, but leaves it invisible and unapplied. If prepare succeeds, the transaction *can* commit
— that is the vote you give your coordinator.

**Commit-prepared** or **rollback-prepared** applies the decision.

Between the two the transaction holds its snapshot and its key reservations. That is real
backpressure: anything contending for those keys is blocked, and the reclamation floor is held
down. **Decide promptly.**

A prepared transaction survives a restart. On the next open,
`tidesdb_recover_prepared` hands back everything that was prepared and never decided, so a
coordinator can finish resolving them. A transaction whose decision *was* logged is settled
during open and never appears.

## Practical guidance

**Pick a level per workload, not per database.** `tidesdb_txn_begin_with_isolation` takes it per
transaction, and a column family carries a default for transactions begun against it. Event
ingestion at read-committed and account updates at snapshot can coexist in one database.

**Keep transactions short**, for the reclamation floor. An open transaction holds a snapshot, and
nothing above that snapshot can be reclaimed while it lives — so a transaction that is never
resolved costs disk for as long as the database is open. Where that cannot be guaranteed by
construction, bound it: `txn_timeout_seconds` for every transaction, or
[`tidesdb_txn_set_timeout`](/reference/transaction#tidesdb_txn_set_timeout) for one. Expiry is
lazy, so the next operation on a stale transaction aborts it and returns `TDB_ERR_TXN_EXPIRED`.

**Retry on conflict, retry on locked.** Both mean "try again"; neither means "it failed".

**Do not reuse a handle after a failed commit** without resetting it. `tidesdb_txn_reset`
re-arms a handle without the free-and-allocate cycle, which is worth it in a tight loop.
