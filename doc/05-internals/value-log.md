---
title: Value log
description: The database-wide store for separated values -- append-only segments, logical ids, and a reclamation that excludes nobody.
slug: internals/value-log
part: internals
sidebar:
  order: 7
---

# Value log

## The problem

A value large enough to dominate a btree node should not be stored in the btree. Separating it
keeps the tree small — a btree holding references instead of kilobyte values has far fewer,
denser nodes, so scans touch less and the cache holds more — and it means a compaction that
rewrites a key does not rewrite its value. That removes what would otherwise be the dominant
cost of compacting large-value data.

This follows **WiscKey** (Lu et al., FAST '16), though the addressing and the reclamation both
differ from it substantially; see [Design lineage](/internals/design-lineage).

Separation creates its own problem. Values written once and referenced from many sstables
accumulate garbage as keys are overwritten and deleted, and reclaiming that garbage means
moving bytes that live readers may be reading.

**A separated value is written at commit, not at flush.** The committing transaction appends the
bytes here and the write-ahead log record carries only the id, so a large value reaches the device
once instead of once in the log and again when the memtable is flushed. What follows from that is
that the value exists before anything durable references it, and stays that way until the memtable
holding the reference is flushed -- which is what the floors below are for.

## Segments

The store is **database-wide**: one set of files serves every column family, because a value's
identity has nothing to do with which family holds the key. It is a series of append-only
segment files named `NNNNNNN.vlog`, of which exactly one is open for appends. That segment seals
when it reaches its target size and a fresh one takes over.

**A sealed segment is immutable for the rest of its life.** Nothing rewrites it, shifts it, or
truncates it. It is read until it is unlinked, and then it is gone.

A klog entry references a value by an **opaque logical id**, never a physical location. The id
names one block for the whole of its life, and nothing in the store ever moves it. What the
indirection buys is that no sstable records *where* a value sits, so ordinary compaction carries
one forward by id without reading, re-encoding or moving it, and a segment nothing references is
unlinked whole without touching a single tree.

Emptying a segment that still holds live values is the one case that rewrites anything, and it
does not relocate them either: the next merge to carry such a value writes it **afresh under a new
id**, into an output table that merge was already building. See [Reclaiming](#reclaiming).

:::note[Why not one file]
The obvious design is one file, compacted in place by shifting survivors down over the gaps and
truncating the tail. It is simpler, and it packs perfectly. It is also impossible to make
concurrent: the shift moves bytes underneath readers, and the closing truncate assumes nothing
was appended above the region being compacted, so both readers and appenders have to be
excluded for the whole rewrite.

The cost of that exclusion is not theoretical. A single pass over a 6.5 GB store takes over two
minutes, and every read, write, flush and compaction in the database blocks behind it. It also
starves: with readers continuously arriving, the exclusive writer never acquires the lock at all
until load stops, and the store grows without bound in the meantime. Segments avoid both because
nothing is ever moved within the store — a segment is either unlinked whole or left alone.
:::

## Reading

A read resolves the id to a segment slot, an offset and a length under the index read lock, drops
that lock, and only then takes a **reference on the segment** before fetching the block. It holds
no lock a reclamation can take.

The reference is acquired *after* the index lock is released rather than under it, which is what
makes acquiring able to fail: a reclaim may retire the segment in that window. That is not an
error but the answer — the id resolved to a segment that no longer exists, so the read reports
the value absent rather than touching a file being unlinked.

The reference is the whole lifetime protocol. It is the same
[refcount with an evicting window](/internals/sstable#lifetime) the sstable uses: a segment rests
at a baseline of one, readers transiently raise it, and an unlink waits for it to fall back.

The resting count is one here and two for an sstable, and the difference is not an inconsistency:
a segment's evictor works from the slot table and takes no reference of its own, while the reaper
that evicts a key log holds one on every candidate it collected. The count the window is claimed at
is always "the structural reference, plus whatever the evicting thread itself holds" — which for a
segment is nothing.

Acquiring a segment also goes through the form that waits the window out rather than reading the
sentinel as a freed object. That is what makes a release inside the window impossible here: a
release can only follow an acquire, and an acquire that had already succeeded would have raised the
count above the baseline and failed the claim.

Every block carries its own id in its payload header, and the read checks it. That is a
correctness check against a stale index rather than a routine one, and it sits alongside the
block manager's checksum: a read either returns the value it asked for or an error, never
somebody else's bytes.

The header carries one more thing: **the chain of encodings the value was written through**, in
the top byte of the length word and the ids following it. The value is decoded with that chain
rather than with the pipeline of whichever family is reading, because the two are not always the
same. Compaction carries a separated value forward by id without re-reading or re-encoding it, so
a value written under one pipeline can end up referenced by an sstable whose footer records
another; and one shared store holds values from families that encode differently. A value that
described itself by anything but its own bytes would eventually be decoded with the wrong chain.

A reader that cannot resolve the chain a value carries — a build without that codec compiled in —
reports the read as corrupt and hands back nothing. That is the one damage a checksum cannot catch:
the block is intact and its bytes are exactly what was written, they simply cannot be turned back
into the value. Answering with the stored bytes would be a silent wrong read, so it is treated as
the same unreadable condition as any other decode failure, and the value reads correctly again from
a build that has the codec.

## Reclaiming

The vlog has **no idea which values are still referenced** — that truth lives in the klogs. Asking
them for it is not affordable: building the live id set that way means scanning every key of every
sstable of every family, on a store shared by all of them, and on a database large enough to need
reclaiming that scan does not finish.

So the trees report rather than being read. Every sstable records at build time **which segments
its separated values landed in and how many bytes of each it holds**, and carries that histogram in
its footer. Summed over the tables installed right now, it is exactly the live bytes of every
segment, and it costs no file read at all.

The tables are not the only holder, though, and the two others have to be added to that sum or the
segments they hold read as empty:

- **A memtable** holds references from the moment a commit separates a value until its flush
  installs. Those are covered by a floor rather than by counting, since a memtable's contents move
  under a reader; see below.
- **A staged prepared batch** holds them for as long as it is undecided. Its entries enter no
  memtable -- that is what a prepare is -- and no sstable names them until phase two decides it, so
  they are counted here alongside the tables.

A pass therefore has two tiers:

1. **A segment nothing holds is unlinked.** Its index entries are dropped and its file is removed.
   Nothing is read, nothing is copied, and no reader is excluded, because nothing can resolve into
   a segment nothing references.
2. **A segment at most half live is marked.** The next compaction that carries one of
   its values forward **writes the value afresh instead of keeping the reference**, so the value
   lands in a current segment and the marked one falls towards zero — where tier one collects it
   for nothing.

The second tier is the whole reason the store never moves bytes itself. Emptying a half-dead segment
is a rewrite of the tables referencing it, and compaction already rewrites tables; doing it there
costs a merge that was going to run anyway. Ordinary compaction is untouched — carrying a reference
forward stays free — and only values in a marked segment pay a read and a write.

**Liveness is restated, not adjusted.** Each pass zeroes what every segment is reported to hold and
sums the histograms afresh. Tracking installs and drops incrementally would be cheaper and is the
wrong trade: the two error directions are not equal. A missed drop only delays reclaiming a segment,
while a missed install makes a segment holding live values look empty, and dropping that loses them.
Restating cannot drift.

:::caution[`vlog_used_bytes` is not live data]
The index names every value the store has ever written that has not had its segment dropped,
reachable or not. It therefore converges on the file size, and a store holding gigabytes of garbage
reports a space amplification near 1. `vlog_live_bytes` is the figure to divide by.
:::

:::caution[The active segment is never reclaimed and never marked]
It is still growing, so the share of it that is live says nothing yet, and rewriting values into the
very segment being emptied would not converge.
:::

### The windows a floor holds

A holder that is not an installed table protects its values with a **floor** — the segment taking
appends when it took one — and nothing at or above the lowest floor in flight is reclaimable. Four
holders take one:

- **A flush** writes its values and only then installs the sstable naming them.
- **A compaction** holds one across its swap, since a re-spill writes before it installs.
- **A memtable** takes one when it becomes the active memtable, so the floor is already in place
  before the first commit that can reach it separates anything. Taking it at the memtable's first
  reference would be too late: the value reaches this store before the commit that produced it
  reaches any memtable, and a pass in that window drops the segment it just landed in.
- **A prepared batch** takes one while it is undecided, beside the write-ahead log generation it
  already pins for the same reason.

A floor is a lower bound on where the holder's values might be, so a holder that adopts a value
written before it existed has to reach further back than the segment it started at. A memtable
receiving a reference the commit separated a moment before a rotation does exactly that, and lowers
its floor onto that value's own segment.

### What it costs

Tier one is free: an unlink and an in-memory index purge. Tier two costs one read and one write per
value, inside a merge already running, and only for values in a marked segment.

Sweeping segment size from 16 MiB to 1 GiB on a sixteen-family churn workload leaves the store
within about 2% of the same size throughout — 3,664 MB at 16 MiB and 3,718 MB at 1 GiB, against
3,745 MB at the 256 MiB default. **Store size is flat across the range**, so segmenting costs no
space worth naming, and the size to pick is decided by the trade below rather than by space.

The half-live bar is what stops the second tier costing more than it recovers, and it cannot be
much stricter than that. Under a random update load segments decay at about the same rate, so they
sit together around half live rather than spreading out; a quarter-live bar is one almost nothing
crosses, which leaves the store holding twice its data with nothing marked.

Segment size carries a real trade. A segment can only be dropped
when *nothing* in it is live, so larger segments mix more values together and one cold key can hold
a whole file open until compaction rewrites it out. Smaller segments reach zero sooner and reclaim
faster; larger ones amortise descriptors and rolls.

`vlog_dead_bytes` says how much there is to reclaim and `vlog_segments_drainable` says how much of
it is currently actionable. Read together in
[`tidesdb_get_db_stats`](/reference/statistics#tidesdb_get_db_stats), a drainable count that stays
high is reclamation falling behind the garbage.

### Descriptors

A store can hold thousands of segments, so segment files are opened against the **same descriptor
budget** as klogs and write-ahead logs, under their own `vlog_segment` label. Exhaustion wakes the
reaper and retries rather than failing the store.

An idle segment's descriptor is also **given back on demand**. The reaper closes sealed segments
nothing is reading and the next read reopens the file, published by a compare-exchange so two
readers racing to reopen cannot both install a handle. A segment with a reader inside it is never
closed: the eviction claims the same reference count a reader takes, so it either wins with the
segment idle or leaves it alone.

### Values larger than a segment

A value is never split. One value is one block, so a value larger than the segment target lands
whole in a fresh segment that simply overshoots it — the target is a **roll threshold, not a size
bound**. The ceiling is instead the block frame: a value whose payload will not fit a uint32 length
is refused with an error rather than truncated.

This is the easiest case for reclamation rather than the hardest. An oversized value effectively
gets a segment to itself, so that segment is either entirely live or entirely dead, and the moment
nothing references it the whole file is dropped without any rewriting.

## What a codec achieved

A family can change its codec, and the tier-two rewrite deliberately re-spills values under the
**merging** family's pipeline — so a store is not written under one encoding, it accumulates values
under several, and migrates between them as compaction runs. A single compression figure for the
store would average across all of that and describe none of it.

So compression is attributed **per chain**, and the chain comes from the value rather than from any
configuration: each value already records the pipeline it was written through in its block header,
because that is what lets a value be carried forward by id and decoded correctly by a family that
encodes differently. `vlog_get_chain_stats` reports, for each chain seen, the uncompressed bytes,
the on-disk bytes, and how many values it accounts for — so `used / stored` is that codec's realised
ratio on the values it actually wrote.

This survives a reopen without being persisted anywhere, because it is rebuilt by reading the chain
back off each value during recovery.

:::caution[A family's codec describes what it will write next]
It does not describe what the family holds. Any figure reporting on stored bytes has to ask the
bytes, or it will credit a codec with data written before it was configured.
:::

## Recovery

On open, every segment in the directory is adopted in ascending number order and its blocks are
scanned to rebuild the id index. Appends then go to a **fresh** segment rather than extending
the newest recovered one, so a segment sealed before a restart stays immutable across it.

Nothing is ever copied within the store, so **an id names one block for its whole life** and a
crash cannot leave the same id in two segments. A pass that dies part way has either unlinked a
segment or not; there is no half-drained state to resolve.

Per-segment liveness is not persisted, and does not need to be. It is summed from the footers of
the tables the manifest says are installed, so the first pass after an open restates it from what
is actually there.

A torn tail, from a crash mid-append, is skipped by the block scan. Nothing else is affected: the
segment is unlinked whole when it is eventually dropped, so there is no gap to reason about.

## Invariants

| Invariant | Why |
| --- | --- |
| A sealed segment is never modified | It is what lets a reader hold an offset without a lock |
| A klog holds a logical id, never a location | The store owns the id-to-segment mapping, so slots can be retired and reused without any sstable recording a file that no longer exists |
| A segment is unlinked only after every reader leaves | The index is repointed first, so no new reader can arrive |
| Of two entries for one id, the higher segment wins | The store copies nothing, so this cannot arise from its own operation; the tiebreak is defensive, resolving a duplicate deterministically rather than by scan order |
| A reclaim never marks the active segment | It is still growing, so the share of it that is live says nothing yet, and rewriting values into the very segment being emptied would not converge |
| A reclaim never retires the segment taking appends | A pass decides a slot is reclaimable and only then retires it, and a roll landing between the two makes the slot it chose the active one. Retiring it unlinks the open file, and every later append then spins on a slot that never reopens and reports the store as out of room. The decision reads the active slot per segment rather than once per pass, and the retire itself re-reads it after claiming the eviction window -- a slot only becomes active by being claimed out of the table, and a claim takes slots reading absent, so past that point the reading is final |
| A segment is marked only when at least half of it is dead | Below that, the rewrite it costs the next compaction is more than the space it returns |
| Liveness is decided by the caller's set, never by the index alone | The index holds dropped values until their segment drains, so it would report garbage as live |
| Every block carries its own id, and reads check it | A stale index must produce an error, never another value's bytes |
| Every block carries the encoding chain it was written through | Compaction carries a value forward without re-encoding it, so the sstable referencing it may record a different pipeline |
| Ids are never reissued | The next id resumes above every id recovered |
