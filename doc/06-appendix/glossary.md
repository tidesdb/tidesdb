---
title: Glossary
description: Terms used throughout this manual.
slug: appendix/glossary
part: appendix
sidebar:
  order: 4
---

# Glossary

**Block** — One framed record in a file: size, checksum, payload, size again, magic. Every file
the engine writes is a sequence of these.

**Block cache** — The database-wide bounded pool every on-disk block read passes through. Caches
parsed objects as well as raw bytes, so a hit skips both the read and the parse.

**Column family** — An independent ordered keyspace within one database. Has its own levels and
compaction policy; shares the memtable, log, value log, and cache with every other family.

**Compaction** — Merging sstables into fewer, larger, deeper ones so reads consult fewer files.

**DCA** — The capacity scheme used by the compaction planner, sizing smaller levels as a fraction
of how much data the largest level actually holds, so capacities adapt to the data rather than
being fixed in advance.

**Dividing level** — The shallowest level whose merges partition their output by the level below's
file boundaries instead of writing one file.

**Output size cap** — The largest a compaction output may grow before the merge rolls to a new
file, derived as a fraction of the largest level's data. It counts key log bytes, so a separated
value costs its reference rather than its length.

**Flush** — Writing a sealed memtable out as sstables. Because the memtable is shared, a flush
covers every column family at once.

**Immutable memtable** — A memtable that has been sealed by a rotation and is awaiting flush.
Still readable; no longer written to.

**Isolation level** — What a transaction's reads may see and what makes its commit fail. Five,
from read-uncommitted to serializable.

**Key log (klog)** — An sstable's file: a btree holding keys and inline values, plus the filter
partitions and the footer.

**Level** — A tier of sstables within a family. L1 holds flush outputs and may overlap; L2 and
below are non-overlapping sorted runs. Shallower is newer.

**Manifest** — The durable catalogue of what exists. Database-level, so a flush across families
is atomic. A file it does not name does not exist.

**Memtable** — The in-memory write buffer. One per database, shared by every family, with keys
namespaced by a four-byte family index prefix.

**MVCC** — Multi-version concurrency control. Writes append new versions rather than overwriting,
so readers never block writers.

**Partition range filter** — A per-sstable bloom filter split by key range, so its resident cost
is bounded by the block cache rather than by the entry count.

**Prepared transaction** — One that has passed phase one of two-phase commit: durably logged,
conflict-checked, but not applied and not visible.

**Read amplification** — How many sstables a point lookup must consult.

**Rotation** — Sealing the active memtable and installing a fresh one. Runs on the committing
thread that filled it.

**Sequence** — The monotonic number every commit draws. Visibility is a comparison against it.

**Snapshot** — A sequence ceiling. A version is visible if it committed at or below it.

**Spooky** — The compaction policy: a pure deterministic planner plus an executor.

**SSTable** — An immutable sorted run on disk. One key log file, plus references into the shared
value log.

**Staging ring** — The in-memory buffer a buffered block manager stages appends in, so concurrent
appenders do not serialize on the file.

**Value separation** — Storing a value at or above `value_separation_threshold` in the value log and
keeping only its id where the key lives. Done by the committing transaction, so the bytes reach the
device once rather than once in the write-ahead log and again in the flush.

**Tombstone** — A version marking a key deleted. Shadows older versions until a merge can prove
none survive beneath it.

**Value log (vlog)** — The database-wide store holding values too large to keep inline, kept as a
series of numbered segment files with one taking appends. A value is addressed by an opaque
logical id, so a merge carries it forward by reference rather than rewriting it. The exception is
a segment marked for draining, whose values the next merge that touches one writes afresh under a
new id so the segment can be dropped.

**Write amplification** — The ratio of bytes written to the device against bytes written by the
application.

**Write-ahead log (WAL)** — The per-generation log a commit reaches before the memtable, so a
crash between the two recovers the batch.
