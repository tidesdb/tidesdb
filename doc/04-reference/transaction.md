---
title: Transaction Operations
description: Beginning, reading, writing, committing, and two-phase-commit coordination.
slug: reference/transaction
part: reference
sidebar:
  order: 3
---

# Transaction Operations

Every read and every write in TidesDB happens inside a transaction. There is no
non-transactional path — a single put is a transaction with one operation in it.

Writes are buffered until commit. A transaction that has put a key can read it back and
will see its own write, but nothing else will until the commit succeeds. Commit writes the
batch to the write-ahead log and then applies it to the memtable, in that order, so a crash
between the two leaves the batch recoverable rather than lost.

A transaction handle is **not thread-safe**. One transaction belongs to one thread at a
time. Several threads may each hold their own transaction against the same database, which
is the normal way to use the engine.

[`tidesdb_txn_request_abort`](#tidesdb_txn_request_abort) is the single exception, and it is
narrow by construction: it stores a flag and changes nothing else, leaving the thread that owns
the transaction to act on it. Everything else here still belongs to one thread.

## Isolation levels

The level fixes two things: which committed versions a read can see, and what makes a
commit fail.

| Level | Value | Reads see | Commit can return `TDB_ERR_CONFLICT` |
| --- | --- | --- | --- |
| `TDB_ISOLATION_READ_UNCOMMITTED` | 0 | Everything, including uncommitted writes | No |
| `TDB_ISOLATION_READ_COMMITTED` | 1 | The latest committed version, re-read per operation | No |
| `TDB_ISOLATION_REPEATABLE_READ` | 2 | A sequence frozen at begin | **Yes**, if a key it read changed |
| `TDB_ISOLATION_SNAPSHOT` | 3 | A sequence frozen at begin | **Yes**, if a key it wrote was written first |
| `TDB_ISOLATION_SERIALIZABLE` | 4 | A sequence frozen at begin | **Yes**, on either |

`TDB_ISOLATION_READ_COMMITTED` is the default, so **conflict detection is opt-in**. Only the lower
two never conflict, and a blind write at `TDB_ISOLATION_READ_COMMITTED` — the default — behaves
like an unchecked overwrite, so a lost update is the expected outcome of a race there rather than
a defect.

The three above it each check something different. Repeatable read validates its **read set**: a
commit fails if any key it recorded a read for has a newer committed version. Snapshot instead
takes a first-committer-wins reservation on every key it **writes**, validated against the version
the transaction actually read, so a write-write race loses at commit rather than silently
overwriting — but it does not check reads. Serializable does both and adds the check for write
skew. **Any code using a level above read-committed must handle `TDB_ERR_CONFLICT` by retrying the
whole transaction.**

## tidesdb_txn_begin

Begin a transaction at the database default isolation level.

### Synopsis

```c
int tidesdb_txn_begin(tidesdb_t *db, tidesdb_txn_t **txn);
```

### Description

Begins at `TDB_ISOLATION_READ_COMMITTED`, which does not detect conflicts. This is a fixed
library default, not a configurable one — the database configuration has no isolation field.
To choose a level use
[`tidesdb_txn_begin_with_isolation`](#tidesdb_txn_begin_with_isolation), or
[`tidesdb_txn_begin_cf`](#tidesdb_txn_begin_cf) to inherit a column family's default.

The handle must be released with [`tidesdb_txn_free`](#tidesdb_txn_free) whatever the
outcome, including after a successful commit.

### Errors

| Code | Cause |
| --- | --- |
| `TDB_ERR_INVALID_ARGS` | `db` or `txn` is `NULL` |
| `TDB_ERR_INVALID_DB` | The database is closing, so no new transaction is admitted |
| `TDB_ERR_MEMORY` | Allocation failed |

### See Also

[`tidesdb_txn_commit`](#tidesdb_txn_commit), [`tidesdb_txn_free`](#tidesdb_txn_free)

## tidesdb_txn_begin_with_isolation

Begin a transaction at an explicit isolation level.

### Synopsis

```c
int tidesdb_txn_begin_with_isolation(tidesdb_t *db, tidesdb_isolation_level_t isolation,
                                     tidesdb_txn_t **txn);
```

### Description

As [`tidesdb_txn_begin`](#tidesdb_txn_begin), with the level given explicitly. See
[Isolation levels](#isolation-levels) for what each one costs and guarantees.

### Errors

Same as [`tidesdb_txn_begin`](#tidesdb_txn_begin), plus `TDB_ERR_INVALID_ARGS` for a level
outside the enum.

### See Also

[`tidesdb_txn_reset`](#tidesdb_txn_reset)

## tidesdb_txn_begin_cf

Begin a transaction at a column family's default isolation level.

### Synopsis

```c
int tidesdb_txn_begin_cf(tidesdb_t *db, tidesdb_column_family_t *cf, tidesdb_txn_t **txn);
```

### Description

Uses `cf`'s `default_isolation_level`. This only picks the level — the transaction is not
confined to that family and may read and write any family.

### Errors

Same as [`tidesdb_txn_begin`](#tidesdb_txn_begin), plus `TDB_ERR_INVALID_ARGS` if `cf` is
`NULL`.

## tidesdb_snapshot_create

Name the database as it stands now, so it can be read again later.

### Synopsis

```c
int tidesdb_snapshot_create(tidesdb_t *db, tidesdb_snapshot_t **snapshot);
```

### Description

Captures the current sequence and **holds the reclamation floor at it**. That hold is the feature:
compaction may not discard versions above the floor, and a flush carries them into L1 for the same
reason, so the state the snapshot names stays readable for as long as it lives.

It is also the cost, and it is the same cost a long-running transaction has. A snapshot left open
pins `min_snapshot_seq` exactly as a forgotten transaction does, and shows up the same way — as
disk that will not reclaim. Release it as soon as the point in time is no longer wanted.

### Errors

| Code | Cause |
| --- | --- |
| `TDB_ERR_INVALID_ARGS` | `db` or `snapshot` is `NULL` |
| `TDB_ERR_INVALID_DB` | The database is closing |
| `TDB_ERR_MEMORY` | Allocation failed |

### See Also

[`tidesdb_txn_begin_at_snapshot`](#tidesdb_txn_begin_at_snapshot),
[`tidesdb_snapshot_release`](#tidesdb_snapshot_release)

## tidesdb_snapshot_release

Release a snapshot and the reclamation floor it held.

### Synopsis

```c
void tidesdb_snapshot_release(tidesdb_snapshot_t *snapshot);
```

### Description

Every transaction opened against the snapshot must be freed first. They read versions only this
snapshot keeps alive, and releasing it lets the next merge collect them.

Passing `NULL` does nothing.

## tidesdb_snapshot_seq

The sequence a snapshot reads at.

### Synopsis

```c
uint64_t tidesdb_snapshot_seq(const tidesdb_snapshot_t *snapshot);
```

### Description

Returns 0 for a `NULL` snapshot. Compare it against `min_snapshot_seq` from
[`tidesdb_get_db_stats`](/reference/statistics#tidesdb_get_db_stats) to see which snapshot is
holding the floor down when reclamation stalls.

## tidesdb_txn_begin_at_snapshot

Begin a transaction that reads as of a snapshot.

### Synopsis

```c
int tidesdb_txn_begin_at_snapshot(tidesdb_t *db, tidesdb_snapshot_t *snapshot,
                                  tidesdb_txn_t **txn);
```

### Description

The same keys and the same families, answered as they stood when the snapshot was taken. Point
reads and scans agree, because both resolve at the transaction's read snapshot.

The snapshot must **outlive** the transaction — it is what holds the floor under the versions being
read.

For a point in time no snapshot was taken at, [`tidesdb_txn_begin_at_seq`](#tidesdb_txn_begin_at_seq)
takes the sequence directly. A snapshot is the stronger form: it holds the floor from the moment it
is taken, so the point stays readable, where a bare sequence is readable only while something else
happens to be holding the floor under it.

Expiry is judged against the clock at the moment of the read, not against the snapshot, so a
snapshot does not bring back an entry whose lifetime has since elapsed. Time travel applies to
versions, not to deadlines.

### Errors

| Code | Cause |
| --- | --- |
| `TDB_ERR_INVALID_ARGS` | `db`, `snapshot` or `txn` is `NULL` |
| `TDB_ERR_INVALID_DB` | The database is closing |
| `TDB_ERR_MEMORY` | Allocation failed |

### Examples

```c
tidesdb_snapshot_t *snap = NULL;
if (tidesdb_snapshot_create(db, &snap) == TDB_SUCCESS)
{
    /* the database moves on */

    tidesdb_txn_t *past = NULL;
    if (tidesdb_txn_begin_at_snapshot(db, snap, &past) == TDB_SUCCESS)
    {
        uint8_t *value = NULL;
        size_t value_size = 0;
        if (tidesdb_txn_get(past, cf, key, key_size, &value, &value_size) == TDB_SUCCESS)
        {
            /* ... the value as of the snapshot ... */
            tidesdb_free(value);
        }
        (void)tidesdb_txn_rollback(past);
        tidesdb_txn_free(past);
    }

    /* the versions it was holding become collectable again here */
    tidesdb_snapshot_release(snap);
}
```

### See Also

[`tidesdb_snapshot_create`](#tidesdb_snapshot_create),
[`tidesdb_txn_read_snapshot`](#tidesdb_txn_read_snapshot)

## tidesdb_txn_begin_at_seq

Begin a transaction that reads as of an explicit sequence.

### Synopsis

```c
int tidesdb_txn_begin_at_seq(tidesdb_t *db, uint64_t seq, tidesdb_txn_t **txn);
```

### Description

For a point in time no snapshot was taken at — a sequence read back from
[`tidesdb_txn_read_snapshot`](#tidesdb_txn_read_snapshot), or one recorded elsewhere.

**It refuses rather than approximates.** The versions an older point resolves to survive only while
the reclamation floor sits at or below it. Once a collection has run past that sequence a merge has
kept one version of each key and dropped the rest, so a read there would answer from what survived
instead of from what was true — most often reporting a key that existed as absent. That case returns
`TDB_ERR_TOO_OLD` and reads nothing.

A sequence is therefore readable while something holds the floor under it: an open transaction, or a
[snapshot](#tidesdb_snapshot_create) taken in advance. On a database with no reader registered the
floor is free to rise, and a sequence stops being reconstructable as soon as it does — which is why
a snapshot is the stronger tool when the point in time is known ahead of time.

The boundary is not guessed at. [`tidesdb_oldest_readable_seq`](#tidesdb_oldest_readable_seq)
reports it, and a sequence at or above it is exact.

A reopened database cannot speak for what an earlier run collected, so the boundary starts at the
sequence recovery resumed from. Points from before a restart are refused.

Expiry is judged against the clock at the moment of the read, so this does not bring back an entry
whose lifetime has elapsed. It travels over versions, not over deadlines.

### Errors

| Code | Cause |
| --- | --- |
| `TDB_ERR_INVALID_ARGS` | `db` or `txn` is `NULL` |
| `TDB_ERR_TOO_OLD` | A collection has already run below `seq`; the point in time cannot be reconstructed |
| `TDB_ERR_INVALID_DB` | The database is closing |
| `TDB_ERR_MEMORY` | Allocation failed |

### See Also

[`tidesdb_oldest_readable_seq`](#tidesdb_oldest_readable_seq),
[`tidesdb_txn_begin_at_snapshot`](#tidesdb_txn_begin_at_snapshot)

## tidesdb_oldest_readable_seq

The oldest sequence still exactly readable.

### Synopsis

```c
uint64_t tidesdb_oldest_readable_seq(const tidesdb_t *db);
```

### Description

The highest reclamation floor any collection has taken. A sequence at or above it names a state the
database can still reconstruct exactly; below it a merge has already dropped versions, and
[`tidesdb_txn_begin_at_seq`](#tidesdb_txn_begin_at_seq) refuses.

It only ever rises. Holding a snapshot or an open transaction is what keeps it from rising past a
point still wanted, which is the same mechanism — and the same cost — as pinning `min_snapshot_seq`.

Returns 0 for a `NULL` database.

## tidesdb_txn_put

Buffer a put.

### Synopsis

```c
int tidesdb_txn_put(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *key,
                    size_t key_size, const uint8_t *value, size_t value_size, time_t ttl);
```

### Description

Buffers a write. Key and value bytes are **copied**, so the caller's buffers may be reused
or freed immediately.

Nothing is durable and nothing is visible to other transactions until
[`tidesdb_txn_commit`](#tidesdb_txn_commit) succeeds.

### An empty value is a value

`value_size` may be zero. The key is then **present carrying nothing**, which is a different state
from being absent: a read returns it with a zero size rather than reporting it missing, and only
[`tidesdb_txn_delete`](#tidesdb_txn_delete) makes a key absent.

```c
/* present, with nothing in it -- the key carries the meaning */
tidesdb_txn_put(txn, cf, key, klen, NULL, 0, 0);
```

This is the natural shape for anything whose meaning is entirely in the key — a secondary index
entry, a set member — which would otherwise have to store a filler byte it does not want.

### The `ttl` parameter

`ttl` is a **lifetime in seconds from now**. Zero or negative never expires.

```c
/* expires one hour from now */
tidesdb_txn_put(txn, cf, key, klen, val, vlen, 3600);

/* never expires */
tidesdb_txn_put(txn, cf, key, klen, val, vlen, 0);
```

The engine converts the lifetime to an absolute deadline **once, at this call**, and stores
that. Two consequences worth knowing:

- The clock starts when you call `put`, not when the transaction commits. A transaction held
  open for a minute after the put has already spent a minute of the entry's life.
- A slow recovery cannot extend an entry's life. Because the write-ahead log carries the
  deadline rather than the lifetime, replay does not restart the clock.

Expiry is evaluated on read and at compaction. An expired entry is invisible before it is
physically removed, so space is reclaimed lazily but visibility is immediate.

### Parameters

| Parameter | Description |
| --- | --- |
| `txn` | Transaction, must be active |
| `cf` | Target column family |
| `key` / `key_size` | Key bytes, copied. `key_size` must be non-zero. |
| `value` / `value_size` | Value bytes, copied. `value_size` may be zero — see below |
| `ttl` | Lifetime in seconds from now; `<= 0` never expires |

### Errors

| Code | Cause |
| --- | --- |
| `TDB_ERR_INVALID_ARGS` | A `NULL` argument or a zero-length key |
| `TDB_ERR_TXN_EXPIRED` | The transaction is no longer active |
| `TDB_ERR_TXN_ABORTED` | Another thread called `tidesdb_txn_request_abort` on the transaction |
| `TDB_ERR_MEMORY` | Allocation failed buffering the operation |

### See Also

[`tidesdb_txn_get`](#tidesdb_txn_get), [`tidesdb_txn_delete`](#tidesdb_txn_delete)

## tidesdb_txn_get

Read a key, recording the read for conflict detection.

### Synopsis

```c
int tidesdb_txn_get(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *key,
                    size_t key_size, uint8_t **value, size_t *value_size);
```

### Description

Reads at the transaction's snapshot and **records the read into the conflict footprint**.
Under snapshot and serializable isolation this is what makes a later write to the same key
validate against the version actually read rather than against the snapshot, so a
read-modify-write is checked properly.

Sees the transaction's own buffered writes first, then the committed state at the snapshot.

`*value` is newly allocated and **owned by the caller** — release it with
[`tidesdb_free`](/reference/database#tidesdb_free), not your own `free`.

Reading a key you do not intend to base a write on inflates the footprint and causes
avoidable conflicts. For existence probes use
[`tidesdb_txn_contains`](#tidesdb_txn_contains) or
[`tidesdb_txn_get_notrack`](#tidesdb_txn_get_notrack).

### Errors

| Code | Cause |
| --- | --- |
| `TDB_ERR_NOT_FOUND` | No visible version, or the newest visible one is a tombstone or expired |
| `TDB_ERR_INVALID_ARGS` | A `NULL` argument or a zero-length key |
| `TDB_ERR_TXN_EXPIRED` | The transaction is no longer active |
| `TDB_ERR_TXN_ABORTED` | Another thread called `tidesdb_txn_request_abort` on the transaction |
| `TDB_ERR_MEMORY` | Allocation failed |
| `TDB_ERR_LOCKED` | Transient contention — retryable, not a miss |
| `TDB_ERR_IO` / `TDB_ERR_CORRUPTION` | Reading an sstable or the value log failed |

`TDB_ERR_LOCKED` is **not** "absent". Treating it as a miss is a correctness bug; retry.

### Examples

```c
uint8_t *value = NULL;
size_t value_size = 0;

int rc = tidesdb_txn_get(txn, cf, key, key_size, &value, &value_size);
if (rc == TDB_SUCCESS)
{
    /* ... use value ... */
    tidesdb_free(value);
}
else if (rc != TDB_ERR_NOT_FOUND)
{
    /* a real error, not an absence */
}
```

### See Also

[`tidesdb_txn_get_notrack`](#tidesdb_txn_get_notrack),
[`tidesdb_txn_contains`](#tidesdb_txn_contains)

## tidesdb_txn_get_notrack

Read a key without recording it for conflict detection.

### Synopsis

```c
int tidesdb_txn_get_notrack(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *key,
                            size_t key_size, uint8_t **value, size_t *value_size);
```

### Description

Identical to [`tidesdb_txn_get`](#tidesdb_txn_get) except that the read is **not** added to
the conflict footprint. For probes whose result does not justify aborting the transaction —
a primary-key uniqueness check, for example, where the answer you care about is "absent" and
a concurrent insert of a *different* key is irrelevant.

Ownership is the same: free `*value` with
[`tidesdb_free`](/reference/database#tidesdb_free).

Using this where the read *does* feed a write weakens the guarantee to blind-write
semantics at snapshot isolation. If the value read decides what you write, use
[`tidesdb_txn_get`](#tidesdb_txn_get).

### Errors

Same as [`tidesdb_txn_get`](#tidesdb_txn_get).

## tidesdb_txn_read_snapshot

Report the sequence the transaction's reads filter at.

### Synopsis

```c
uint64_t tidesdb_txn_read_snapshot(const tidesdb_txn_t *txn);
```

### Description

Returns the sequence ceiling this transaction reads at, so a caller can reason about which
committed versions are and are not visible. Diagnostic; nothing in the API consumes it.

| Level | Value returned |
| --- | --- |
| `TDB_ISOLATION_READ_UNCOMMITTED` | `UINT64_MAX` |
| `TDB_ISOLATION_READ_COMMITTED` | The current sequence, moving with each read |
| Repeatable read and stronger | The sequence frozen at begin |

Returns 0 for a `NULL` transaction, which is otherwise not a valid snapshot.

### Thread Safety

Reads transaction state; observe the same one-thread-per-transaction rule.

## tidesdb_txn_contains

Existence check without allocating or tracking.

### Synopsis

```c
int tidesdb_txn_contains(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *key,
                         size_t key_size);
```

### Description

Reports whether a visible, unexpired, non-tombstoned version exists at the snapshot. Does
not allocate and does not record the read into the conflict footprint.

Cheaper than [`tidesdb_txn_get`](#tidesdb_txn_get) when the value is not needed, especially
for a value that lives in the value log — the check is answered without dereferencing it.

### Return Value

`TDB_SUCCESS` if present, `TDB_ERR_NOT_FOUND` if absent, otherwise an error as for
[`tidesdb_txn_get`](#tidesdb_txn_get) — including `TDB_ERR_TXN_EXPIRED` when a timeout has passed
and `TDB_ERR_TXN_ABORTED` when another thread has requested an abort. `TDB_ERR_LOCKED` again means
retry, not absent.

## tidesdb_txn_delete

Buffer a delete.

### Synopsis

```c
int tidesdb_txn_delete(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *key,
                       size_t key_size);
```

### Description

Buffers a tombstone. Deleting a key that does not exist is not an error — the tombstone is
written regardless, since the engine cannot know at buffer time whether a version exists in
some lower level.

The tombstone occupies space until a compaction can prove no older version of the key
survives beneath it. Delete-heavy workloads are what
`tombstone_density_trigger` exists to compact.

### Errors

Same as [`tidesdb_txn_put`](#tidesdb_txn_put).

### See Also

[`tidesdb_txn_single_delete`](#tidesdb_txn_single_delete),
[`tidesdb_txn_delete_prefix`](#tidesdb_txn_delete_prefix)

## tidesdb_txn_single_delete

Buffer a delete that supersedes at most one put.

### Synopsis

```c
int tidesdb_txn_single_delete(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *key,
                              size_t key_size);
```

### Description

A tombstone carrying a **promise from the caller**: this key was written at most once, so
the tombstone and that single put annihilate as soon as a compaction sees them together,
instead of the tombstone being retained until every level below has been proven clear.

**Breaking the promise resurrects data.** If the key was written more than once, the
tombstone and the newest put cancel, and an older put underneath becomes visible again. Use
it only for keys written exactly once — insert-once identifiers, for example. When in doubt
use [`tidesdb_txn_delete`](#tidesdb_txn_delete), which is always safe.

### Errors

Same as [`tidesdb_txn_put`](#tidesdb_txn_put).

## tidesdb_txn_delete_prefix

Buffer a delete of every key under a prefix.

### Synopsis

```c
int tidesdb_txn_delete_prefix(tidesdb_txn_t *txn, tidesdb_column_family_t *cf,
                              const uint8_t *prefix, size_t prefix_size);
```

### Description

Buffers one entry that deletes every key in the family beginning with `prefix`, however many
keys that is. It shadows keys written before it as well as keys written after it, so it is not
the same as deleting the keys that happen to exist when you call it.

This is what a family-per-tenant shape does not need and a prefix-per-tenant shape does. The
data model steers you toward prefixes inside one family rather than thousands of families, and
this is the operation that makes removing one of those prefixes cheap to write.

A write to a key under the prefix survives the delete when it is newer — buffered after it in
the same transaction, or committed at a later sequence:

```c
/* both land, and user:1 is alive afterwards while its siblings are not */
tidesdb_txn_delete_prefix(txn, cf, (const uint8_t *)"user:", 5);
tidesdb_txn_put(txn, cf, (const uint8_t *)"user:1", 6, val, vlen, 0);
```

**The write is O(1); the reclamation is not.** The keys stay on disk until a compaction
rewrites the range, and reads pay a bounded interval lookup until then. What you buy is the
write and the atomicity, not immediate space.

`prefix_size` must be greater than zero and at most `TDB_MAX_RANGE_BOUND_SIZE` (256), for the
reason given under [`tidesdb_txn_delete_range`](#tidesdb_txn_delete_range). Dropping a whole family
is [`tidesdb_drop_column_family`](/reference/column-family#tidesdb_drop_column_family), which unlinks
its files rather than walking its keys.

### Choosing between this and a range

A prefix names the interval `[prefix, successor(prefix))`, so this is
[`tidesdb_txn_delete_range`](#tidesdb_txn_delete_range) with the one bound a prefix implies.
Reach for the prefix form when the thing you are removing genuinely *is* a prefix — a tenant, a
partition, an id's versions — because it says so at the call site and cannot get its bounds
wrong. Reach for the range form when the boundary falls somewhere a prefix cannot put it.

### Isolation

At `TDB_ISOLATION_SNAPSHOT` and above the commit is refused with `TDB_ERR_CONFLICT` when any
key under the prefix was written after this transaction drew its snapshot. The reverse is
refused too: a write to a key under a prefix another transaction is deleting conflicts, which
is what makes the two orderings symmetric.

A commit carrying a prefix delete runs alone against other committing transactions, so the
check is still true by the time it commits. A two-phase transaction takes that exclusion only
for its prepare — the window before phase two resolves it has no bound, and holding it there
would stall every other committer for as long as the transaction stayed undecided. What covers
that window instead is the prefix itself, held from the prepare until phase two, so a write
under it is refused for as long as it stays in doubt.

### Errors

| Code | Meaning |
| --- | --- |
| `TDB_ERR_INVALID_ARGS` | `txn`, `cf` or `prefix` is NULL, `prefix_size` is zero, or it exceeds `TDB_MAX_RANGE_BOUND_SIZE` |
| `TDB_ERR_TXN_EXPIRED` | The transaction is no longer active |
| `TDB_ERR_TXN_ABORTED` | Another thread called `tidesdb_txn_request_abort` on the transaction |
| `TDB_ERR_MEMORY` | Allocation failed buffering the operation |

### See Also

[`tidesdb_txn_delete`](#tidesdb_txn_delete)

## tidesdb_txn_delete_range

Buffer a delete of every key in a range.

### Synopsis

```c
int tidesdb_txn_delete_range(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *lo,
                             size_t lo_size, const uint8_t *hi, size_t hi_size);
```

### Description

Buffers one entry that deletes every key from `lo` inclusive to `hi` exclusive, however many keys
that is. Like a prefix delete it shadows keys written before it as well as keys written after it,
and a newer write to a key inside the range survives it.

The bounds fall wherever you put them. They do not have to line up with any component of the key,
which is what separates this from [`tidesdb_txn_delete_prefix`](#tidesdb_txn_delete_prefix):

```c
/* a window inside a tenant, where no prefix covers the range and nothing else */
tidesdb_txn_delete_range(txn, cf, (const uint8_t *)"acme|20260105", 13,
                         (const uint8_t *)"acme|20260120", 13);
```

**The upper bound is exclusive.** A key equal to `hi` survives. Passing `NULL` with `hi_size` of
zero leaves the range open above, so it runs to the end of the column family.

**`hi` must be above `lo`.** An interval ending where it starts, or before it, covers no key. It is
refused here with `TDB_ERR_INVALID_ARGS` rather than accepted and met later, because what would meet
it runs after the batch is durable, where a failure is taken for a transient one and retried — so a
bound you could still fix would instead cancel the whole transaction and report a disk error. The
rest of the batch is unaffected by the refusal, and the transaction stays usable.

`lo_size` must be greater than zero. Keys are never empty, so a single zero byte is a lower bound
below every key there can be:

```c
/* everything in the family below a bound */
tidesdb_txn_delete_range(txn, cf, (const uint8_t *)"\x00", 1, (const uint8_t *)"m", 1);
```

**Each bound is at most `TDB_MAX_RANGE_BOUND_SIZE` (256) bytes.** A range delete holds its bounds
in a fixed slot for the length of its commit — that slot is what stops a concurrent write landing
inside the range while the commit is still undecided, and there is no slot wide enough for an
arbitrary bound. A longer one is refused here with `TDB_ERR_INVALID_ARGS` rather than narrowed,
because a narrowed bound would delete a range the caller never asked for. A range too wide to name
in one call is expressed as several.

**The write is O(1); the reclamation is not.** The keys stay on disk until a compaction rewrites
the range, and reads pay a bounded interval lookup until then. What you buy is the write and the
atomicity, not immediate space. Dropping a whole family is
[`tidesdb_drop_column_family`](/reference/column-family#tidesdb_drop_column_family), which unlinks its
files rather than walking its keys.

### Isolation

The same as [`tidesdb_txn_delete_prefix`](#tidesdb_txn_delete_prefix): at
`TDB_ISOLATION_SNAPSHOT` and above, a commit is refused with `TDB_ERR_CONFLICT` when any key in
the range was written after this transaction drew its snapshot, and a write to a key inside a
range another transaction is deleting is refused the same way.

### Errors

| Code | Meaning |
| --- | --- |
| `TDB_ERR_INVALID_ARGS` | `txn`, `cf` or `lo` is NULL, `lo_size` is zero, `hi` is at or below `lo`, or either bound exceeds `TDB_MAX_RANGE_BOUND_SIZE` |
| `TDB_ERR_TXN_EXPIRED` | The transaction is no longer active |
| `TDB_ERR_TXN_ABORTED` | Another thread called `tidesdb_txn_request_abort` on the transaction |
| `TDB_ERR_MEMORY` | Allocation failed buffering the operation |

### See Also

[`tidesdb_txn_delete_prefix`](#tidesdb_txn_delete_prefix),
[`tidesdb_txn_delete`](#tidesdb_txn_delete)

## tidesdb_txn_commit

Commit a transaction.

### Synopsis

```c
int tidesdb_txn_commit(tidesdb_txn_t *txn);
```

### Description

Validates conflicts if the isolation level requires it, draws a commit sequence, reserves
the written keys, writes the batch to the write-ahead log, and applies it to the memtable.
The log write happens before the memtable apply, so a crash in between recovers the batch
rather than losing it.

What "durable" means when this returns depends on the database sync mode: under
`TDB_SYNC_FULL` the batch is on the device; under `TDB_SYNC_INTERVAL` it has left the process
into the operating system's page cache, so it survives process death, and reaches the device
within the configured interval; under `TDB_SYNC_NONE` it is only staged in the log's ring, still
inside this process, so a kill takes it with it. See [Durability](/concepts/durability).

Commit may **block** on write admission if the flush queue is backed up. This is
backpressure, not a fault.

On failure the transaction is aborted. It cannot be retried by calling commit again — begin
a new transaction, or reuse this one with [`tidesdb_txn_reset`](#tidesdb_txn_reset).

The handle still has to be freed with [`tidesdb_txn_free`](#tidesdb_txn_free) after a
successful commit.

### Errors

| Code | Cause |
| --- | --- |
| `TDB_ERR_CONFLICT` | Another transaction committed a conflicting write first. Only at snapshot and serializable. **Retry the whole transaction.** |
| `TDB_ERR_INVALID_ARGS` | `txn` is `NULL` or not active |
| `TDB_ERR_TXN_EXPIRED` | The transaction is no longer active |
| `TDB_ERR_TXN_ABORTED` | Another thread called `tidesdb_txn_request_abort` on the transaction |
| `TDB_ERR_IO` | The write-ahead log append failed |
| `TDB_ERR_MEMORY` | Allocation failed |

### Examples

```c
for (int attempt = 0; attempt < MAX_RETRIES; attempt++)
{
    tidesdb_txn_t *txn = NULL;
    if (tidesdb_txn_begin(db, &txn) != TDB_SUCCESS) break;

    tidesdb_txn_put(txn, cf, key, key_size, value, value_size, 0);

    int rc = tidesdb_txn_commit(txn);
    tidesdb_txn_free(txn);

    if (rc != TDB_ERR_CONFLICT) break;   /* done, or a real failure */
}
```

### See Also

[`tidesdb_txn_rollback`](#tidesdb_txn_rollback),
[`tidesdb_txn_prepare`](#tidesdb_txn_prepare)

## tidesdb_txn_rollback

Discard a transaction's buffered writes.

### Synopsis

```c
int tidesdb_txn_rollback(tidesdb_txn_t *txn);
```

### Description

Throws away everything buffered. Nothing was written to the log or the memtable, so there is
no undo to perform and rollback cannot fail for I/O reasons.

The handle still has to be freed with [`tidesdb_txn_free`](#tidesdb_txn_free).

### Errors

`TDB_ERR_INVALID_ARGS` if `txn` is `NULL` or not in a rollbackable state.

## tidesdb_txn_set_timeout

Bound how long a transaction may stay active.

### Synopsis

```c
int tidesdb_txn_set_timeout(tidesdb_txn_t *txn, int64_t seconds);
```

### Description

Sets a deadline `seconds` from now, overriding the database's `txn_timeout_seconds` for this
transaction alone. Pass `0` or less to clear any bound.

**Why this exists.** An active transaction holds its snapshot, and at snapshot and serializable
isolation its write reservations too. That keeps the reclamation floor down, so compaction cannot
drop the old versions below it and the value log cannot reclaim their bytes. A transaction that is
never resolved therefore costs disk for as long as the database stays open. A timeout is what
bounds that for a caller that might leak one.

**Expiry is lazy and reported once.** Nothing aborts the transaction in the background. The next
operation on it notices the deadline has passed, aborts it, and returns `TDB_ERR_TXN_EXPIRED`.
After that the transaction is resolved rather than expired, so further operations report
`TDB_ERR_INVALID_ARGS`. The handle still has to be freed with
[`tidesdb_txn_free`](#tidesdb_txn_free).

The deadline is measured from the call, not from the begin, so calling it again on a live
transaction extends it rather than accumulating.

The clock behind it advances once a second, so a bound is accurate to about a second and is not
suited to sub-second deadlines.

### Parameters

| Parameter | Description |
| --- | --- |
| `txn` | Transaction |
| `seconds` | Seconds from now at which it expires, or `<= 0` to clear the bound |

### Errors

`TDB_ERR_INVALID_ARGS` if `txn` is `NULL` or is no longer active.

## tidesdb_txn_request_abort

Abort a transaction another thread is running.

### Synopsis

```c
void tidesdb_txn_request_abort(tidesdb_txn_t *txn);
```

### Description

The one call in this API that may be made on a transaction owned by a different thread.

**Why this exists.** The engine decides between two transactions racing on the same key by
first-committer-wins, and reports the loser `TDB_ERR_CONFLICT`. But a caller can itself be the
authority on whether a transaction may proceed — a replication plugin whose cluster has already
certified against this one, say — and the engine has no way to know a ruling has been made
elsewhere. This is how that ruling gets in.

**It stores a flag and does nothing else.** The transaction is not rolled back here, and no state
changes on the calling thread — which is what keeps the one-thread-per-transaction rule intact.
The thread running the transaction sees the flag when it next enters an operation, aborts it
there, and returns [`TDB_ERR_TXN_ABORTED`](/appendix/error-codes). That thread then frees the
handle as it normally would.

**Every operation afterwards reports the same code**, the commit included. That matters more than
it looks: if a read happened to be the operation that noticed, a later commit reporting only
"transaction finished" would lose the very fact the caller needs at the point it most needs to
report it.

**Phase two is the exception.** A transaction already in the prepared state has voted, and
[`tidesdb_txn_commit_prepared`](#tidesdb_txn_commit_prepared) and
[`tidesdb_txn_rollback_prepared`](#tidesdb_txn_rollback_prepared) proceed regardless of a
request. Once a participant has voted, only the coordinator's decision may resolve it — letting a
local flag override that would leave one participant abandoning a transaction the others committed.
Abort a transaction before it prepares, or abandon it through the coordinator afterwards.

The code is deliberately not `TDB_ERR_CONFLICT`. A caller layered over the engine has to tell an
outside ruling from the engine's own verdict, because the two mean different things to whatever it
reports upwards.

:::caution[The abort takes effect at the next operation, not instantly]
A request landing just after the running thread has checked lets the operation in progress finish
and stops the one after it. A caller that needs the abort to take effect before a particular
operation must not be racing that operation — it is expected to be holding the transaction still by
its own means, exactly as it would to abort a transaction anywhere else.
:::

Calling it more than once is harmless, as is calling it on a transaction that has already
resolved, where it has no effect. A `NULL` transaction is a no-op.

### Parameters

| Parameter | Description |
| --- | --- |
| `txn` | Transaction to abort, or `NULL` |

### Thread Safety

Safe to call from any thread, including one that does not own the transaction. That is the point
of it.

## tidesdb_txn_prepare

Two-phase commit, phase one.

### Synopsis

```c
int tidesdb_txn_prepare(tidesdb_txn_t *txn, const uint8_t *xid, size_t xid_size);
```

### Description

Runs the same conflict checks as commit and durably logs the write batch under `xid`, but
leaves the writes **invisible and unapplied** so a coordinator can collect votes from every
participant before deciding.

On success the transaction is `TDB_TXN_STATE_PREPARED` and holds its snapshot and its key
reservations until resolved with
[`tidesdb_txn_commit_prepared`](#tidesdb_txn_commit_prepared) or
[`tidesdb_txn_rollback_prepared`](#tidesdb_txn_rollback_prepared). Holding reservations
blocks conflicting commits, so an undecided prepared transaction applies backpressure to
everything contending for its keys — decide promptly.

A read-only transaction prepares with nothing durable and needs no phase two.

The `xid` is copied. It is the coordinator's identifier and the engine only stores and
returns it.

Once prepared, the transaction survives a restart:
[`tidesdb_recover_prepared`](#tidesdb_recover_prepared) hands it back in doubt.

### Errors

| Code | Cause |
| --- | --- |
| `TDB_ERR_CONFLICT` | Conflict detected at phase one — the transaction is aborted, not prepared. Also raised when too many prepared transactions are undecided at once, since each one holds a slot until it is resolved |
| `TDB_ERR_INVALID_ARGS` | `NULL` `txn` or `xid`, `xid_size` of 0, or a transaction not in the active state |
| `TDB_ERR_TXN_EXPIRED` | The transaction is no longer active |
| `TDB_ERR_TXN_ABORTED` | Another thread called `tidesdb_txn_request_abort` on the transaction |
| `TDB_ERR_IO` / `TDB_ERR_MEMORY` | The prepare record could not be logged |

### See Also

[`tidesdb_txn_state`](#tidesdb_txn_state)

## tidesdb_txn_commit_prepared

Two-phase commit, phase two — commit.

### Synopsis

```c
int tidesdb_txn_commit_prepared(tidesdb_txn_t *txn);
```

### Description

Durably logs the decision, then applies the batch and makes it visible. Valid **only** on a
prepared transaction.

The batch lands at a sequence drawn now, when the decision is made, not at the sequence it
held when it prepared. That is what keeps replay ordering correct: a key written by another
transaction between the prepare and the decision is correctly superseded by this one, rather
than being shadowed by a stale sequence.

A transient I/O failure leaves the transaction **prepared**, not aborted, so the coordinator
can retry the same decision.

### Errors

| Code | Cause |
| --- | --- |
| `TDB_ERR_INVALID_ARGS` | `txn` is `NULL` or not prepared |
| `TDB_ERR_IO` / `TDB_ERR_MEMORY` | The decision could not be logged; the transaction stays prepared and the call may be retried |

## tidesdb_txn_rollback_prepared

Two-phase commit, phase two — roll back.

### Synopsis

```c
int tidesdb_txn_rollback_prepared(tidesdb_txn_t *txn);
```

### Description

Durably logs the decision to abandon the prepared transaction and releases its reservations.
Nothing had been applied, so nothing is undone. The decision is logged rather than merely
dropped so that a restart does not resurrect the transaction as in-doubt.

A transient I/O failure leaves it prepared for retry, as with
[`tidesdb_txn_commit_prepared`](#tidesdb_txn_commit_prepared).

### Errors

Same as [`tidesdb_txn_commit_prepared`](#tidesdb_txn_commit_prepared).

## tidesdb_recover_prepared

List transactions left in doubt by a restart.

### Synopsis

```c
int tidesdb_recover_prepared(tidesdb_t *db, tidesdb_prepared_txn_t *out, int max, int *out_count);
```

### Description

Returns the transactions durably prepared before the last shutdown that were never decided,
so a coordinator can finish them. One whose decision *was* logged is settled during
[`tidesdb_open`](/reference/database#tidesdb_open) and never appears here.

The set is fixed when the database opens, so the two-call pattern is safe: call once with
`out` as `NULL` to learn the count, allocate, then call again to fill.

Each entry's `txn` is a real handle in the prepared state — resolve it with
[`tidesdb_txn_commit_prepared`](#tidesdb_txn_commit_prepared) or
[`tidesdb_txn_rollback_prepared`](#tidesdb_txn_rollback_prepared) and free it with
[`tidesdb_txn_free`](#tidesdb_txn_free) like any other. The `xid` is **borrowed** from the
database and valid until it is closed; copy it if you need it longer.

### Errors

| Code | Cause |
| --- | --- |
| `TDB_ERR_INVALID_ARGS` | `db` or `out_count` is `NULL` |
| `TDB_ERR_TOO_LARGE` | `out` was given and `max` is below the real count. `*out_count` is still set, **nothing was written, and no handles were created** — so there is nothing to free before retrying with a bigger buffer. |
| `TDB_ERR_MEMORY` | Allocation failed |

### Examples

```c
int count = 0;
if (tidesdb_recover_prepared(db, NULL, 0, &count) == TDB_SUCCESS && count > 0)
{
    tidesdb_prepared_txn_t *pending = malloc(sizeof(*pending) * (size_t)count);

    if (tidesdb_recover_prepared(db, pending, count, &count) == TDB_SUCCESS)
    {
        for (int i = 0; i < count; i++)
        {
            /* ask the coordinator what was decided for pending[i].xid */
            tidesdb_txn_rollback_prepared(pending[i].txn);
            tidesdb_txn_free(pending[i].txn);
        }
    }
    free(pending);   /* your allocation, your free */
}
```

## tidesdb_txn_state

Report a transaction's lifecycle state.

### Synopsis

```c
int tidesdb_txn_state(const tidesdb_txn_t *txn, tidesdb_txn_state_t *out_state);
```

### Description

Reports one of `TDB_TXN_STATE_ACTIVE`, `TDB_TXN_STATE_PREPARED`, `TDB_TXN_STATE_COMMITTED`,
or `TDB_TXN_STATE_ABORTED`. Mainly for coordinators distinguishing a prepared transaction
from a resolved one.

### Errors

`TDB_ERR_INVALID_ARGS` if `txn` or `out_state` is `NULL`.

## tidesdb_txn_reset

Reset a transaction for reuse.

### Synopsis

```c
int tidesdb_txn_reset(tidesdb_txn_t *txn, tidesdb_isolation_level_t isolation);
```

### Description

Discards buffered state and returns the handle to active at `isolation`, avoiding a
free/allocate cycle in a loop that runs many small transactions. A new snapshot is taken, so
a reset transaction sees everything committed up to that moment.

Resetting an uncommitted transaction discards its writes — the effect of a rollback.

### Errors

| Code | Cause |
| --- | --- |
| `TDB_ERR_INVALID_ARGS` | `txn` is `NULL`, or `isolation` is outside the enum |
| `TDB_ERR_MEMORY` | Allocation failed re-arming the transaction |

## tidesdb_txn_free

Free a transaction handle.

### Synopsis

```c
void tidesdb_txn_free(tidesdb_txn_t *txn);
```

### Description

Releases the handle, **rolling it back first if it is still open**. Passing `NULL` is safe.

Must be called for every handle from any `begin`, and after a successful commit as well —
committing does not free.

Freeing a **prepared** transaction without deciding it abandons the handle while the
prepared batch stays durable on disk; it comes back as in-doubt from
[`tidesdb_recover_prepared`](#tidesdb_recover_prepared) after the next open. Decide before
freeing unless that is what you intend.

## tidesdb_txn_savepoint

Mark a savepoint.

### Synopsis

```c
int tidesdb_txn_savepoint(tidesdb_txn_t *txn, const char *name);
```

### Description

Names a point in the buffered write sequence to roll back to later. Savepoints nest: marking
several and rolling back to an earlier one discards the later ones too.

Names are the caller's; reusing a name shadows the earlier mark.

### Errors

| Code | Cause |
| --- | --- |
| `TDB_ERR_INVALID_ARGS` | `txn` or `name` is `NULL`, or the transaction is already resolved |
| `TDB_ERR_TXN_EXPIRED` | A timeout has passed; the transaction is aborted by this call |
| `TDB_ERR_TXN_ABORTED` | Another thread called `tidesdb_txn_request_abort` on the transaction |
| `TDB_ERR_MEMORY` | Allocation failed |

## tidesdb_txn_rollback_to_savepoint

Roll back to a savepoint.

### Synopsis

```c
int tidesdb_txn_rollback_to_savepoint(tidesdb_txn_t *txn, const char *name);
```

### Description

Discards every operation buffered after `name` was marked, leaving the transaction active
and everything before it intact. The savepoint itself remains, so the same name can be
rolled back to again.

### Errors

| Code | Cause |
| --- | --- |
| `TDB_ERR_NOT_FOUND` | No savepoint by that name |
| `TDB_ERR_INVALID_ARGS` | `txn` or `name` is `NULL`, or the transaction is already resolved |
| `TDB_ERR_TXN_EXPIRED` | A timeout has passed; the transaction is aborted by this call |
| `TDB_ERR_TXN_ABORTED` | Another thread called `tidesdb_txn_request_abort` on the transaction |

## tidesdb_txn_release_savepoint

Release a savepoint.

### Synopsis

```c
int tidesdb_txn_release_savepoint(tidesdb_txn_t *txn, const char *name);
```

### Description

Forgets the mark, keeping every buffered operation. Releasing a savepoint does **not**
discard work — it only makes that point no longer available to roll back to, along with any
savepoints nested inside it.

### Errors

Same as [`tidesdb_txn_rollback_to_savepoint`](#tidesdb_txn_rollback_to_savepoint).
