---
title: Recovery
description: What happens on open -- rebuilding the catalogue, replaying the logs, reseeding the clock, and adopting in-doubt transactions.
slug: internals/recovery
part: internals
sidebar:
  order: 15
---

# Recovery

## The problem

A database can stop at any instant: mid-append, mid-flush, mid-compaction, mid-manifest-commit.
On the next open the on-disk state must be resolved into exactly one answer — **everything
acknowledged is present, and nothing else is**.

Recovery is not a special mode. It runs on every open, and a clean shutdown is just the case
where there is little to do. That is deliberate: a recovery path exercised only after crashes is
a recovery path that does not work.

## Order of operations

```
  1. open the manifest         -> rebuild the family registry and level sets
  2. open the value log
  3. sweep unnamed key logs    -> reclaim what an interrupted build left behind
  4. scan NNNNNNN.log          -> the surviving write-ahead log generations
  5. replay each generation    -> one sealed memtable per generation, in order
  6. install a fresh active memtable above them
  7. reseed the sequence clock
  8. adopt in-doubt prepared transactions
  9. queue the recovered generations for flush
```

The order is forced by dependency. Families must exist before log records naming them can be
applied. The clock must be reseeded before anything new is written, or a fresh commit could
reuse a sequence that durable data already holds.

The sweep sits where it does for a reason at each end. It has to follow the catalogue, since the
catalogue is what says which files are reachable. It has to come before the workers start, because
once a flush or compaction is running there is a window in which a file exists and the manifest
does not name it yet — and a sweep cannot tell that from an orphan.

## Rebuilding the catalogue

The manifest is replayed to reconstruct the family registry and each family's level set. What
it names, exists; what it does not name, does not — so orphaned files from an interrupted flush
or compaction are never half-adopted. Having established that, recovery then deletes them: a key
log outside the catalogue can never be reached again, so leaving it costs disk and buys nothing.
The one exception is a self-healed manifest, where the catalogue was derived from the files and
sweeping against it would destroy what the rebuild could not adopt.

A manifest that will not read back does not fail the open. The discarded catalogue is rebuilt from
the sstables themselves: the database directory is scanned and every `.klog` whose footer reads back
is re-registered at L1, its owning family taken from the family id in its filename. The footer is
self-describing enough to adopt a file, but it records neither the family's name nor the level the
file sat at -- so a rebuilt family is named `cf_` followed by its zero-padded id, carries the default
configuration, and its tables land in the one tier that permits overlap. See [Manifest](/internals/manifest) for the two cases and the limits of the rebuild.

The rebuild adopts at most 4096 families, a guard against a corrupt directory rather than a limit a
real database approaches. It says how many families and sstables it took at warn either way, and
says separately, at error, when it stopped at that bound — a count on its own reads as the whole
directory, and the families past the bound are left uncatalogued with their files still on disk.

## Replaying the logs

Each surviving `NNNNNNNNNNNN.log` is replayed in generation order, and each becomes a sealed
memtable in the queue with a fresh active memtable installed above them. The recovered database
therefore has **exactly the shape a running one has** — no special post-recovery state, no
second code path for reads. The recovered generations are then flushed through the ordinary
flush machinery.

Replay reads framed blocks forward and stops at the first one it cannot read. A torn final
record — a crash mid-append — ends replay there, which is correct: that record was never
acknowledged.

:::caution[A hole is not a skipped record]
Because replay stops at the first unreadable block, a gap in the middle of a log discards
**everything after it**, silently. Nothing in recovery can detect that; the guarantee has to come
from the write side, where only the contiguous completed run is ever written. See
[Block manager](/internals/block-manager).
:::

Records carry their own sequence, so replay applies each at the sequence it committed with
rather than at its position in the file. File order and sequence order need not agree, and
correctness comes from the sequence.

:::caution[An entry a durable later write already retired is not applied]
A log can outlive the flush that installed its data. That happens on purpose when an undecided
prepare lives in it, since a prepared batch exists nowhere else, and by accident when a crash lands
between the install commit and the unlink.

Applying such a log again would be wrong, not merely wasteful. Reads take the **first** source that
answers and consult the memtables before any sstable, which is sound only because a memtable holds
writes newer than anything on disk. An entry restored from an old log breaks that: a put would sit
in front of the tombstone that retired it, and a deleted key would come back.

So replay drops an entry when the sstables already hold a **strictly newer version of that same
key**. Dropping it cannot change any answer, since the newer version would have won either way. The
question is asked of the sstables directly rather than through the ordinary read stack, which at
this point is reading the very memtables being rebuilt. Any answer short of a definite yes keeps the
entry: applying one that was already superseded costs a redundant version, dropping one that was not
is data loss.

The probe is cheap in the ordinary case. Every entry is asked about, since a watermark covering the
whole database cannot stand in for the question, but each table records the highest sequence it
holds and one above that is skipped without a descent. After a clean shutdown the only surviving log
is the one the active memtable was never flushed from, whose sequences are all above every table's,
so every skip applies.
:::

**Not every durable batch is applied.** A batch that reached the log but failed to enter the
memtable is followed by a `TDB_WAL_KIND_ABORT_SEQ` record naming its sequence, because a write batch's
presence in the log is otherwise taken as its commitment — the transaction would come back whole
after its caller was told it failed. Replay gathers those sequences before applying anything, so
a batch can be skipped by a record that appears after it, and applies the rest.

## Reseeding the clock

The counter must resume above **everything durable**, and no single source knows what that is.
Four are consulted, and the highest wins:

| Source | Why it can be the highest |
| --- | --- |
| WAL replay high-water | The most recent commits, normally |
| Manifest sequence | Records catalogue progress independently |
| Recovered sstable maximum | A flushed generation whose log was already unlinked leaves its sstable as the only record of those sequences |
| Prepared transaction maximum | An in-doubt transaction reserved a sequence nothing applied |

The third is the one that is easy to miss. Once a flush retires a memtable and unlinks its log,
those sequences exist only inside the resulting sstable's footer. Reseeding from the logs alone
would reissue them.

The fourth matters for a different reason: a prepared transaction's sequence was drawn but not
applied, so nothing on the data path records it. Skipping it would hand a new writer the same
sequence the coordinator may yet commit at.

## In-doubt transactions

A `PREPARE` record with no matching `COMMIT` or `ROLLBACK` after it is **staged**, not applied.
Its batch is held, its sequence is accounted for in the reseed, and it surfaces through
[`tidesdb_recover_prepared`](/reference/transaction#tidesdb_recover_prepared) as a live handle in
the prepared state.

A prepare whose decision *was* logged is settled during open and never appears — recovery
applies the decision as part of replay rather than leaving it for the caller.

The staging map is carried across every generation, because a prepare and its decision can land
in different logs. A transaction prepared before a rotation and committed after it must be
resolved, not reported as in doubt.

## Self-healing a torn flush

A crash during a flush can leave a partially written sstable. Its key log is a block-manager
file, so the same last-block validation that repairs a torn log applies: the file is truncated
back to its last valid block.

The reason this is safe is the ordering established elsewhere — the manifest names a table only
after that table is durable. A partially written sstable is therefore not in the catalogue, and
whatever is recovered from it is discarded along with the rest of the orphan. The data it was
carrying is still in the write-ahead log, which is why the log is unlinked only after its data
reaches L1.

## What recovery guarantees

**Every acknowledged commit is present.** It was in the log before it was acknowledged, and the
log is replayed.

**Nothing unacknowledged is present.** A torn record ends replay; an orphaned file is not in the
catalogue.

**No sequence is reissued.** The clock resumes above the highest of four durable high-water marks.

**No decided transaction is left in doubt, and no undecided one is decided for you.** Decisions
in the log are applied; prepares without them are handed back.

The crash fuzzer tests exactly this: it commits under a sync barrier, kills the process, reopens,
and verifies that the recovered state is an **exact prefix** of what was acknowledged — not a
superset, not a subset.

## Invariants

| Invariant | Why |
| --- | --- |
| Recovery runs on every open, not only after a crash | An exercised-only-on-crash path does not work |
| Families are rebuilt before log records are applied | A record names a family that must already exist |
| The clock is reseeded before any new write | Otherwise a fresh commit reuses a durable sequence |
| The reseed consults sstables, not just logs | A flushed generation's log may already be unlinked |
| The reseed consults prepared transactions | Their sequences were drawn but never applied |
| Replay applies at the record's own sequence | File order and commit order need not agree |
| The staging map spans generations | A prepare and its decision can land in different logs |
| An entry the sstables already superseded is not applied | Reads take the first source that answers and memtables come before sstables, so an entry restored from a log that outlived its flush would shadow the write that retired it |
| A log is unlinked only after its data reaches L1 | Until then it is the only durable copy |
| The orphan sweep runs after the catalogue and before the workers | The catalogue says what is reachable; a running worker legitimately holds a file the manifest has not named yet |
| A self-healed manifest is never swept against | Its catalogue came from the files, so the sweep would delete exactly what the rebuild could not adopt |
