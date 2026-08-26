---
title: Manifest
description: The durable catalogue of what exists -- one log for the whole database, so a flush across families is atomic.
slug: internals/manifest
part: internals
sidebar:
  order: 8
---

# Manifest

## The problem

Files appear and disappear constantly: a flush creates several, a compaction creates some and
deletes others. A crash can land anywhere in that. Recovery has to answer one question without
ambiguity — **which files are part of the database right now?**

Scanning the directory cannot answer it. A `.klog` on disk might be a live table, a
half-written flush output, or an input a compaction had finished with but not yet unlinked.
The bytes look identical.

So the set is recorded explicitly, and the record is the authority. **A file the manifest does
not name does not exist.** A crash mid-flush leaves orphaned files rather than a corrupt
database, and the orphans are simply ignored.

## One manifest, not one per family

The manifest is database-level. Every column family's tables are recorded in the same log.

This exists to make cross-family flush atomic. One sealed memtable holds keys for several
families, so flushing it produces several sstables that must all become visible together —
otherwise a transaction that atomically wrote to two families would be recoverable in one and
not the other. One log means one append makes all of them live at once.

## Structure

An append-only block-manager log. Each commit appends **one framed block** holding a batch of
records:

```
  [ version:1 ][ record ][ record ][ record ] ...
```

Each record is one opcode plus fixed fields, self-delimiting so a batch is walked without an
index:

| Record | Meaning |
| --- | --- |
| `MANIFEST_OP_CF_ADD` / `MANIFEST_OP_CF_DROP` | A column family appears or goes, with its opaque config blob |
| `MANIFEST_OP_ADD_P` | An sstable joins a level, with its counts, size, and partition |
| `MANIFEST_OP_MOVE` | An sstable changes level without being rewritten |
| `MANIFEST_OP_REMOVE` | An sstable leaves the set |
| `MANIFEST_OP_SEQ` / `MANIFEST_OP_CF_SEQ` | Sequence and family-id high-water marks |
| `MANIFEST_OP_RANGE_DEL` | One family's whole set of [range deletes](/reference/transaction#tidesdb_txn_delete_range), as an opaque blob |

The config blob is stored **verbatim and never interpreted**. The manifest does not know what
a column family configuration contains — that belongs to the configuration module — so the
format can change without touching this one.

`MANIFEST_OP_RANGE_DEL` is the one record that **replaces** rather than adds: it carries a family's
entire interval set, so the newest one replay meets is the set and a rollover writes one per family
that has any. Keeping them here rather than in the sstables is what lets a family that deleted a
range but wrote no keys still record it — a flush that builds no sstable has nothing to hang it on,
and an sstable with no keys cannot be placed in a level set at all.

`MANIFEST_OP_MOVE` deserves note: promoting an sstable to a deeper level when nothing needs merging is a
catalogue edit, not a rewrite. The file stays where it is and the manifest re-points it.

## Committing

A commit is a batch, not a record. Operations accumulate into a pending buffer and are written
as one block, which is what makes a multi-file flush atomic — the block is either a complete
readable block or it is not there at all, and framing makes that decidable.

Durability follows the database sync mode, except that the manifest is part of the **durable
base**: both full and interval durability fsync it, and only `TDB_SYNC_NONE` skips. Interval
mode batches the write-ahead log, never the catalogue.

:::caution[A failed commit keeps the edit and loses the record]
Only the log record is batched. An add or a remove applies to the **live set immediately** and
queues its record alongside; the commit is what writes the queued records out. When the commit
fails it drops them and leaves the live set exactly as the edit left it.

So a caller that treats a failed commit as "nothing happened" is wrong in the direction that
matters. In memory the catalogue already names the new tables; on disk it does not, and no later
commit re-sends the lost records because they are gone from the pending buffer. The next
**rollover** writes the whole live set as a snapshot, at which point the edit becomes durable —
so an entry left behind here is not transient, it is waiting to be made permanent.

That is why the flush and compaction paths undo their own edits when their commit fails: the
outputs are withdrawn from the live set and, for a compaction, the inputs are named again at the
levels they came from. Without it the catalogue would go on naming tables no level set ever took,
and a rollover would eventually write that out as the truth.
:::

## Rollover

An append-only log grows forever, and replay time grows with it. So the log is periodically
rewritten as a single **snapshot block** holding the whole live set — the family registry,
every live sstable, each family's range tombstone set, then the sequence records that close it.

Rollover triggers when records since the last snapshot exceed
`max(512, 2 × live entries)`. Tying it to the live set rather than a fixed count is what
bounds replay to a small multiple of what is actually there, while amortizing the O(N)
snapshot to O(1) per commit.

The rewrite is done safely: the snapshot is written to a temp file beside the manifest, made
durable, then **atomically renamed** over it. A crash before the rename leaves the old
manifest intact; after it, the new one. There is no window where the file is partially
replaced. The temp name carries a thread id and pid so two concurrent rollovers cannot collide,
and under a syncing mode the parent directory is fsynced too — otherwise the rename itself
could be lost while both files survive.

:::caution[A rollover replaces the file, so a reader outside the log needs a hold]
"Append-only" describes the common path, not every path. A rollover renames a different file
over the same name, so anything reading the manifest by path — the [backup](/reference/maintenance#tidesdb_backup)
copy, notably — cannot measure its length at one moment and read the bytes at another. Both have
to happen inside one `tidesdb_manifest_hold`, which a commit and a rollover alike wait on. A
length measured outside a hold can describe a file that no longer exists, and the bytes read
under it are then a truncated snapshot, or a complete but newer one naming files the reader does
not have.
:::

:::caution[A snapshot must carry the high-water marks]
A snapshot emits only the *live* set. Without the explicit `MANIFEST_OP_SEQ` and `MANIFEST_OP_CF_SEQ` records, replay
of a snapshot taken after a family was dropped would derive the next family id from the
largest surviving one — and reissue an id that a dropped family had used. The high-water marks
are raised, never merely stored, so replaying an older snapshot cannot walk them backwards.
:::

## Recovery and self-heal

Replay reads blocks forward, applying each batch. A batch whose fields would overrun its
payload is treated as truncated, which is what a torn final commit looks like.

The interesting decision is what happens when the manifest is damaged. It could refuse to
open. It does not — because **the sstables on disk are the real ground truth**, and their
footers are self-describing enough to rebuild the catalogue from.

Two cases, both self-healing:

- **The header will not validate** — a garbage or truncated file. The manifest is discarded and a
  fresh log started, then **rebuilt from the files on disk**: the database directory is scanned,
  every `.klog` in it reopened, and each one whose footer reads back is re-registered under the
  family id its filename carries.
  Without that step the sstables would still be there and still be readable, and nothing would
  reference them.
- **Corruption partway through** — the readable prefix is kept and the log is immediately
  rewritten as a clean snapshot, discarding the unreadable remainder.

The rebuild recovers what the files carry and no more, which sets two limits worth knowing before
you rely on it:

- **A family comes back named for its id** — the zero-padded `cf_` form rather than the name you
  gave it — because the name lived only in the manifest, while a key log carries its family's id
  in its own filename. Rename it back with
  [`tidesdb_rename_column_family`](/reference/column-family#tidesdb_rename_column_family).
- **A family comes back on default configuration**, for the same reason, and **every adopted
  sstable is placed at L1**, because no file records the level it sat at. L1 is the one tier whose
  members may overlap, so it is the only placement that cannot be wrong. Versions resolve by
  sequence rather than by level, so this costs compaction work rather than correctness.

A `.klog` whose footer will not read — a file a crash left half-written — is skipped and left on
disk rather than adopted.

Both are reported at warn level in the log, not through the return value, so
[`tidesdb_open`](/reference/database#tidesdb_open) succeeds. That is a deliberate trade:
refusing to open a database whose data is intact, because its index was damaged, is worse than
rebuilding the index.

## Ordering with the rest of the engine

The manifest commit is the **publication point**, and everything else is arranged around it:

- A **flush** builds its sstables and makes them durable, *then* commits the manifest. A crash
  before the commit leaves orphans; after it, the tables are live.
- A **compaction** commits its outputs and its input removals in one batch, so the set never
  contains both the inputs and their replacement, nor neither.
- A **create column family** commits before publishing the family in memory, so a crash can
  never leave a live family the manifest does not know about.

## Invariants

| Invariant | Why |
| --- | --- |
| A file the manifest does not name does not exist | Makes orphans harmless and recovery unambiguous |
| One commit is one framed block | Framing is what makes a multi-file change atomic |
| Data is durable before the manifest names it | Otherwise the catalogue references bytes that never landed |
| A snapshot carries `MANIFEST_OP_SEQ` and `MANIFEST_OP_CF_SEQ` | Live-set-only snapshots would let ids and sequences be reissued |
| High-water marks are raised, never stored | Replaying an older snapshot must not walk them back |
| Rollover is write-temp-then-rename | No window where the catalogue is partially replaced |
| A damaged manifest is rebuilt from the sstables | The tables are the ground truth; the catalogue is derived, so it can be re-derived |
