---
title: Error Codes
description: Every public error code, what produces it, and which ones mean "try again".
slug: appendix/error-codes
part: appendix
sidebar:
  order: 1
---

# Error Codes

Every public function returns `TDB_SUCCESS` (0) or one of these. They are negative, so
`rc < 0` tests for failure and `rc != TDB_SUCCESS` is equivalent.

| Code | Value | Meaning |
| --- | --- | --- |
| `TDB_SUCCESS` | 0 | Success |
| `TDB_ERR_MEMORY` | -1 | Allocation failed |
| `TDB_ERR_INVALID_ARGS` | -2 | A `NULL` or out-of-range argument, or a configuration that failed validation |
| `TDB_ERR_NOT_FOUND` | -3 | The key, column family, or savepoint does not exist |
| `TDB_ERR_IO` | -4 | A read, write, or fsync failed |
| `TDB_ERR_CORRUPTION` | -5 | On-disk data did not decode |
| `TDB_ERR_EXISTS` | -6 | A column family with that name already exists |
| `TDB_ERR_CONFLICT` | -7 | Another transaction committed a conflicting write first |
| `TDB_ERR_TOO_LARGE` | -8 | A value does not fit the space that holds it — a buffer too small, or a database that has used every column family id |
| `TDB_ERR_MEMORY_LIMIT` | -9 | A configured memory limit was reached |
| `TDB_ERR_INVALID_DB` | -10 | The database is closing or otherwise unusable |
| `TDB_ERR_UNKNOWN` | -11 | An error with no more specific code |
| `TDB_ERR_LOCKED` | -12 | Transient contention — retry |
| `TDB_ERR_READONLY` | -13 | A write was attempted against a read-only database |
| `TDB_ERR_TXN_EXPIRED` | -14 | The transaction is no longer active |
| `TDB_ERR_NO_SPACE` | -15 | The device or filesystem is out of space |
| `TDB_ERR_TXN_ABORTED` | -16 | Another thread aborted the transaction through `tidesdb_txn_request_abort` |
| `TDB_ERR_TOO_OLD` | -17 | The sequence asked for is older than the oldest reconstructable point in time |

## The two that mean "ask again"

Neither is a failure. Both say the operation did not happen and could succeed if repeated, and
the damaging mistake is to record either as a permanent error — above all to mistake one for an
absent key.

### `TDB_ERR_CONFLICT`

From any level above `TDB_ISOLATION_READ_COMMITTED`, and only from `commit` or `prepare`. Nothing
durable was written; the transaction is aborted.

What was violated depends on the level, and the two causes are different events. At
`TDB_ISOLATION_REPEATABLE_READ` a key **you read** gained a newer committed version. At
`TDB_ISOLATION_SNAPSHOT` a key **you wrote** was written by someone who committed first.
`TDB_ISOLATION_SERIALIZABLE` reports either, and additionally the write-skew check.

**Retry the whole transaction** — begin again, redo the reads, redo the writes. Retrying just
the commit is meaningless, since the reads it was validated against are stale.

### `TDB_ERR_LOCKED`

Contention the engine could not absorb on your behalf. Where you meet it depends on what you
asked for, and the two cases are not equally common.

**From a maintenance call** — `tidesdb_compact`, `tidesdb_compact_range`,
`tidesdb_cf_update_runtime_config`, `tidesdb_rename_column_family`,
`tidesdb_clone_column_family`, `tidesdb_backup` — it means another exclusive operation already
holds that family. `tidesdb_flush_memtable`, and `tidesdb_checkpoint` through it, report it for a
related but distinct reason: the immutable queue had not drained when their bounded wait expired,
which says flush is behind rather than that anything holds a family.
This is the ordinary case. `tidesdb_compact`, `tidesdb_compact_range`,
`tidesdb_cf_update_runtime_config` and `tidesdb_backup` report it **immediately** rather than park
you behind a compaction that could run for minutes. `tidesdb_rename_column_family` and
`tidesdb_clone_column_family` differ: they wait out a bounded quiesce window — a minute — and report
locked only if the family was still held at the end of it, because both have to reach a moment when
nothing else is working on the family. Either way, retry later, or don't; the work you asked for is
in many cases already happening.

**From a read or a scan** it is rare. Transient pressure — a memtable rotating out from under a
reader, a momentarily exhausted descriptor budget — is waited out inside the engine, because a
caller told "try again" has no lever the engine does not already have. Reaching a caller means
the pressure outlasted every internal recheck.

**It never means "not found".** A read returning `TDB_ERR_LOCKED` is saying the data may well
exist but could not be reached right now. Code that folds it into an absence produces silent
wrong answers under load — the single most common way to misuse this API.

Retry with a short backoff.

## Which functions produce what

| Code | Typically from |
| --- | --- |
| `TDB_ERR_CONFLICT` | `tidesdb_txn_commit`, `tidesdb_txn_prepare`, at any level above `TDB_ISOLATION_READ_COMMITTED` |
| `TDB_ERR_LOCKED` | `tidesdb_compact`, `tidesdb_compact_range`, `tidesdb_cf_update_runtime_config`, `tidesdb_rename_column_family`, `tidesdb_clone_column_family`, `tidesdb_backup`; `tidesdb_flush_memtable` and `tidesdb_checkpoint` when the immutable queue does not drain in time; `tidesdb_range_stats` when the layout moves mid-scan; rarely, reads, iterator steps and `tidesdb_iter_new` under pressure the engine could not absorb |
| `TDB_ERR_NOT_FOUND` | `tidesdb_txn_get`, `tidesdb_txn_contains`, family and savepoint lookups |
| `TDB_ERR_EXISTS` | `tidesdb_create_column_family`, `tidesdb_clone_column_family` |
| `TDB_ERR_TXN_EXPIRED` | The first operation on a transaction whose timeout has passed. Only when a timeout was set, by `txn_timeout_seconds` or `tidesdb_txn_set_timeout`; it is reported once and the transaction is then aborted |
| `TDB_ERR_TXN_ABORTED` | Every operation on a transaction after another thread called `tidesdb_txn_request_abort` on it, the commit included. Distinct from `TDB_ERR_CONFLICT` on purpose: a conflict is the engine's own verdict between two writers, where this says an outside authority ruled and the engine never weighed in |
| `TDB_ERR_TOO_OLD` | `tidesdb_txn_begin_at_seq` for a sequence a collection has already run below. It is not a transient condition and retrying never clears it -- the versions that point named are gone, and the boundary only moves further away. Hold a snapshot in advance for a point in time you know you will want |
| `TDB_ERR_INVALID_DB` | Operations against a closing database |
| `TDB_ERR_TOO_LARGE` | `tidesdb_recover_prepared` when the buffer is too small, and `tidesdb_create_column_family` when the family id space is spent |
| `TDB_ERR_CORRUPTION` | Open and read paths, on undecodable on-disk data |
| `TDB_ERR_NO_SPACE` | `tidesdb_flush_memtable`, `tidesdb_checkpoint`, and any path that writes an sstable |

## `TDB_ERR_NO_SPACE`

The device or filesystem could not take the write. It is separated from `TDB_ERR_IO` because it
is the one write failure that says what to do about it: **nothing is damaged, and the operation
succeeds once space is freed.** A generic I/O error carries no such promise, and treating a full
disk as one is how a filled device gets mistaken for a defect in the engine.

Quota exhaustion (`EDQUOT`, where the platform defines it) reports the same code, since it is the
same condition and the same remedy.

Data already committed is unaffected. What fails is the attempt to write new files — a flush, a
compaction, a checkpoint — so the memtable and its log keep the data until a flush can land it. Free
space and retry.

The engine also logs the condition once per failing file, with the remaining free space, so it is
distinguishable in a log without reproducing it.

## Turning a code into text

```c
const char *tidesdb_strerror(int code);
```

Returns a short description of any result code, for a log line or an error message. The string is
a static literal: never `NULL`, never freed, valid for the life of the process. An unrecognised
code describes itself as unknown rather than returning `NULL`, so a result can be passed straight
through without being checked first.

```c
int rc = tidesdb_txn_commit(txn);
if (rc != TDB_SUCCESS) fprintf(stderr, "commit failed, %s\n", tidesdb_strerror(rc));
```

It describes the code, not the cause. Which key, which family, and which file are yours to add.

## Handling pattern

```c
int rc;
int attempts = 0;

do {
    rc = tidesdb_txn_get(txn, cf, key, key_size, &value, &value_size);
} while (rc == TDB_ERR_LOCKED && ++attempts < MAX_RETRIES);

if (rc == TDB_SUCCESS)
{
    /* use value, then free it */
    tidesdb_free(value);
}
else if (rc == TDB_ERR_NOT_FOUND)
{
    /* genuinely absent */
}
else
{
    /* a real failure */
}
```

Note the three-way split. Collapsing "absent" and "failed" into one branch is the shape that
hides `TDB_ERR_LOCKED`.

## On `TDB_ERR_CORRUPTION`

It means bytes did not decode — a damaged file, a truncated record, a foreign file in the
directory. It does **not** always mean data loss:

- A damaged **manifest** is discarded and rebuilt from the sstables on disk, and does not surface as an error at all — though a rebuilt family comes back named `cf_` followed by its zero-padded id, with the default configuration.
- A torn **final record** in a log is discarded during recovery; it was never acknowledged.
- A corrupt **sstable block** is a genuine problem: restore from a backup.

If corruption appears on a healthy disk, suspect the storage stack before the engine, and check
whether anything else is writing into the database directory.
