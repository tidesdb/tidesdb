---
title: SSTable
description: The immutable sorted run on disk -- btree key log, partition range filter, self-describing footer, and the shared value log.
slug: internals/sstable
part: internals
sidebar:
  order: 6
---

# SSTable

## The problem

A flush turns a memtable into a file that will be read many times and never modified. That
file has to support point lookups, ordered scans in both directions, and MVCC — several
versions of a key, each visible to some snapshots and not others — while staying cheap enough
that having many of them is affordable.

Immutability is what makes the rest tractable. Nothing rewrites an sstable in place, so
readers need no locks against writers, and the only lifetime question is when the *file* may
be deleted.

## What one sstable is

A single `CCCCCCCCCC.SSSSSSS.klog` file — the owning family's id and then the table's, each
zero-padded — containing, in order:

```
  +-------------------------------------------------+
  |  btree nodes          leaves, then the levels   |
  |                       above them                |
  +-------------------------------------------------+
  |  filter partitions    the aux region, written   |
  |  + directory          when the build finalizes  |
  +-------------------------------------------------+
  |  footer               fixed head + variable tail|
  +-------------------------------------------------+
```

Values above the database's `value_separation_threshold` are not in this file at all. They live in
the **shared, database-wide value log**, and the entry holds a reference. An sstable owns
exactly one file — its key log — and borrows the value log per call.

## The footer makes the file self-describing

The last block is a footer holding everything needed to use the file: format version, the
btree root and first/last leaf offsets, where the filter directory lives, the key and
tombstone counts, the highest sequence, the byte totals, the btree shape, the minimum and
maximum key, and the encoding pipeline the file was written through.

Opening an sstable therefore requires only the file. Nothing needs to be reconstructed from a
sidecar, and nothing needs to be looked up in the manifest first — which is what lets recovery
treat the sstables as ground truth and rebuild an unreadable manifest from them.

The footer has a fixed-size head followed by a variable tail (the two bounding keys and the
encoding list), each length-prefixed and bounds-checked against what remains, so a truncated or
lying footer is rejected rather than read past.

The **btree node size is recorded in the footer** rather than taken from the current
configuration. A file must be read with the geometry it was written with, and configuration
can change between the write and the read.

The same applies to the encoding pipeline, and more sharply. The builder copies the family's
pipeline once when it is constructed, then both encodes the nodes and writes the footer from that
copy. It has to be one copy: the pipeline it is handed belongs to the live column family
configuration, a runtime reconfigure replaces that whole configuration, and a builder that read it
once to choose its codec and again to fill in the footer could straddle the change — writing nodes
under the old chain and recording the new one. The file would open, and every node read would then
decode with the wrong chain. Nothing later can repair it, because the footer is the only record of
how the bytes were written.

## The btree key log

The sorted store and the index are the same structure. There is no separate index block: a
lookup descends the btree to a leaf.

Leaves are laid out to hold as much as possible in as few bytes as possible:

- **Prefix compression.** Each key stores only the suffix it does not share with its
  predecessor. Sorted keys with common prefixes — which is most real key spaces — collapse.
- **A key indirection table.** Fixed-width offsets to each key's suffix, so a binary search
  within a leaf is O(1) per probe instead of a walk.
- **Delta-encoded sequences.** Sequences are stored relative to a per-node base, so nearby
  sequences cost a byte or two rather than eight.
- **Varints throughout** for sizes and metadata.

Leaves are doubly linked, which is what makes scans O(1) per step in both directions once
positioned, and backward iteration possible at all.

MVCC is **native to the btree** rather than layered over it: a lookup takes a sequence ceiling
and resolves to the newest version at or below it during the descent. There is no
read-then-filter step.

:::note[Node size and the read window]
The block manager's first read fetches a fixed 4 KB window. A node sized just above it costs a
second read on every access. Node size and that window are chosen together — see
[Block manager](/internals/block-manager).
:::

## The partition range filter

A bloom filter answers "is this key definitely absent?" and lets a lookup skip a file
entirely. The difficulty is that one filter over a whole sstable is sized by the entry count,
so a large table means a large resident filter, and many tables mean many of them resident at
once.

So the filter is **split by key range**. The key space is divided, in sorted write order, into
partitions; each partition gets an ordinary bloom filter serialized as its own blob. Only a
small directory of partition first-keys stays resident. The partition blobs are fetched on
demand and live in the block cache, which means **the filter's memory cost is bounded by the
cache rather than by the data size**.

The directory holds each partition's *full* first key, so routing a query to its partition is
exact. That matters: an approximate routing could send a query to the wrong partition and get
a false negative, and a bloom filter that can report a false negative is worse than no filter.

The partitions are accumulated during the build and written together at the end, so the
btree's data blocks stay contiguous rather than being interleaved with filter blobs.

## The shared value log

A value at or above the database's `value_separation_threshold` is not stored in the btree. The
entry holds an opaque logical id instead, and the bytes live in the database-wide
[value log](/internals/value-log).

That is why a compaction rewriting a key does not rewrite its value: it copies the reference
forward. Values are written once and survive any number of merges, which removes what would
otherwise be the dominant cost of compacting large-value data.

**A flush usually copies a reference rather than making one.** The committing transaction already
put the value in the value log, so the entry arriving from the memtable carries an id and the
builder emits it unchanged. It still separates a value itself when one reaches it inline — a family
that opted out with `keep_values_inline`, or a value that was under the threshold when it was
written and is being merged under a larger one. The trade is one extra read when
a point lookup actually wants a separated value, and the API is shaped so most patterns never
pay it — key-only iteration and
[`tidesdb_txn_contains`](/reference/transaction#tidesdb_txn_contains) never dereference at all.

## Lifetime

An sstable is immutable, but its *file* and its *descriptor* both need lifetimes, and they are
not the same lifetime.

**The object** is reference counted. A level set holds one reference for as long as the table
is installed; readers take transient references while inside. A compaction that replaces a
layout drops the old layout's references, and the table is freed by whichever thread drops the
last one — which may be the compaction or a reader still finishing. An installed table rests at
one reference, and a reaper that has collected it holds a second, so what tells the reaper no
reader is in flight is the table sitting at the level set's reference **plus its own**. The check
is an exact match, so a resting count named without the collector's reference never matches and
nothing is ever reclaimed.

**The descriptor** is separate and scarcer. A table may stay installed and readable while its
file descriptor is closed to stay within the budget; the next read reopens it. This is why an
sstable read can report busy: the object is alive, but opening its file would exceed the
budget, and that is retryable backpressure rather than an error.

## How a build fails

The builder writes the btree, finalizes the filter, appends the footer, and makes the file
durable — in that order, and the order is the recovery story. A crash at any point before the
manifest names the file leaves an orphan: a complete or partial `.klog` that nothing refers
to. Recovery ignores it, because the manifest is the catalogue and a file it does not name
does not exist.

**A build that fails without the process dying cleans up after itself** — flush and compaction
both unlink the file they were writing before returning the error. What survives is the case where
the process died: a `.klog` the manifest never got to name, and any `.klog.lstmp` staging file
beside it.

Those are swept at the next open. The manifest is the catalogue, so a key log it does not name is
by definition unreachable, and the sweep removes it before any worker starts — while nothing can
yet be writing a file the manifest has not caught up with. A database that has crashed repeatedly
mid-build therefore gives the space back on restart rather than carrying it until someone deletes
the files by hand.

The sweep is skipped entirely when the manifest was **self-healed**. That path rebuilds the
catalogue *from* the sstables on disk, so for that one open the files are the source of truth
rather than the other way round — and the files it would delete are exactly the ones the rebuild
could not adopt, which is the last copy of whatever they hold. They are left for an operator.

The build also **trims the key log to its data** before that barrier, giving back the preallocated
extent it grew through. An sstable holds its block manager open for as long as it is installed, so
the trim that runs at close would never reach it — see
[Block manager](/internals/block-manager#giving-the-tail-back).

That is why the durability barrier on the key log comes **before** the manifest commit. The
reverse would let the manifest name a file whose bytes never landed.

The value log is deliberately *not* synced by flush or compaction. Its segments carry the
database's own durability mode instead: under `TDB_SYNC_INTERVAL` and `TDB_SYNC_FULL` they are
opened so that each write is durable when it returns — `O_DSYNC` where the platform has it, a
per-write `fdatasync` where it does not — so values are already on the device by the time a key log
can reference them. Under `TDB_SYNC_NONE` the segments are opened unsynced like everything else,
which is that mode's whole promise; the value log is no weaker than the log the keys arrived on.

That inheritance is what removes the need for a barrier, and it is why weakening it is not a local
change. Opening segments unsynced under a mode that syncs — without adding an explicit value-log
barrier ahead of the manifest commit — would leave a durable key log pointing at value bytes that
were never written, and nothing in the test suite would say so.

## Invariants

| Invariant | Why |
| --- | --- |
| An sstable is never modified after it is finalized | Readers take no locks against writers |
| The key log is durable before the manifest names it | Otherwise the catalogue can reference bytes that never landed |
| A finished key log is trimmed to its data | Preallocation advanced the file's logical end; a live sstable never closes, so nothing else would give the extent back |
| The footer records the geometry the file was written with | Configuration may have changed since |
| The footer's encoding pipeline is the one the nodes were actually encoded with | The builder takes the family's pipeline once at construction and both encodes and records from that copy; reading it twice lets a reconfigure land in between and produces a file no encoding in it can decode |
| The filter directory holds full first keys | Approximate routing would produce false negatives |
| A value log id outlives every key log that holds it | Values are shared across merges, and only the value log may retire one |
| A table is freed by whoever drops the last reference | Evictor or reader — whoever is last |
| An exhausted descriptor budget is busy, not absent | The table exists; only the descriptor is unavailable |
| A key log the manifest does not name is swept at open | Unreachable by construction, so the space is pure loss — except after a self-heal, where the files are the catalogue's source and are kept |
