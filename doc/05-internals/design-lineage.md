---
title: Design Lineage
description: The published work TidesDB builds on, what it implements faithfully, and where it deliberately diverges.
slug: internals/design-lineage
part: internals
sidebar:
  order: 19
---

# Design Lineage

Two published designs shape TidesDB's storage layer, and a third shapes its write path. This
chapter states what each contributes, what TidesDB implements as published, and — more usefully —
where it departs and why.

Being explicit about the departures matters. A reader who knows the papers will otherwise assume
behaviour TidesDB does not have.

Full citations are in [References](/appendix/references).

## The papers

**Spooky** — Niv Dayan, Tamar Weiss, Shmuel Dashesky, Michael Pan, Edward Bortnikov, Moshe
Twitto. *Spooky: Granulating LSM-Tree Compactions Correctly.* PVLDB 15(11), 2022, pp. 3071–3084.
Shapes compaction.

**WiscKey** — Lanyue Lu, Thanumalayan Sankaranarayana Pillai, Andrea C. Arpaci-Dusseau, Remzi H.
Arpaci-Dusseau, University of Wisconsin–Madison. *WiscKey: Separating Keys from Values in
SSD-Conscious Storage.* FAST '16. Shapes key/value separation.

**Aether** — Ryan Johnson, Ippokratis Pandis, Radu Stoica, Manos Athanassoulis, Anastasia
Ailamaki. *Aether: A Scalable Approach to Logging.* PVLDB 3(1), 2010. Shapes the write-ahead
log's append path.

## Spooky, and what TidesDB takes from it

Spooky's problem is that the two classical compaction granularities each fail differently. Full
Merge compacts a whole level at once, so "while compacting the LSM-tree's largest level, there
must be at least twice as much storage space" — space amplification is exorbitant. Partial Merge
picks individual files whose key ranges do not perfectly overlap, so it rewrites non-overlapping
data superfluously and interspersing files of different lifetimes worsens SSD garbage collection.

Spooky's answer is to partition the largest level into equal-sized files and partition smaller
levels **on the largest level's file boundaries**, so exactly one group of perfectly overlapping
files merges at a time.

### What TidesDB implements as published

**The dividing level.** In the paper a compaction into level `L-1` is a *dividing merge*, and its
output is partitioned so each output file overlaps at most one file at level `L`. TidesDB computes

```
X = num_levels - 1 - dividing_level_offset      clamped to [1, num_levels - 1]
```

where an offset of 0 gives exactly the paper's `L-1`, and `COMPACTION_SPLIT_BOUNDARIES` is the
dividing merge itself. TidesDB **defaults the offset to 1**, putting the dividing level at `L-2`
rather than at `L-1` — a departure the paper's own measurements argue for, since at `L-1` a
dividing merge rewrites a level holding a tenth of the data in one go. See
[Compaction](/internals/compaction#the-dividing-level).

**The full preemptive merge.** Before any partitioned merge, the paper picks the smallest level
that could absorb everything at and below it without exceeding its capacity, and merges into that;
when no level in range can absorb it, the merge goes to the dividing level. TidesDB's target
selection is that rule — it accumulates level sizes from the shallowest upward and takes the first
whose capacity covers the running total.

**Dynamic Capacity Adaptation.** DCA is not Spooky's invention — the paper attributes it to
RocksDB and *leverages* it, because without it a newly added largest level has far more capacity
than data, and durable space amplification "may be two or greater". DCA sets the capacities of
levels `1..L-1` from the largest level's **data size** rather than its capacity, bounding durable
space amplification to `1/(T-1)`.

TidesDB implements it directly:

```
C_L = base · T^(L-1)               the largest level keeps a geometric capacity
C_i = N_L / T^(L-i)   for i < L    smaller levels track the largest level's actual data
```

### What TidesDB adds

**A pure planner.** Spooky presents an algorithm; TidesDB separates the decisions from the I/O
entirely. The planner takes a snapshot of level sizes and file counts and returns decisions with
no I/O, no handles, and no clock, so the policy is tested by supplying numbers rather than by
building trees on disk. The paper does not prescribe this, and it is the main reason the policy is
verifiable at all.

**Two triggers the paper does not have**, both needed in practice:

- **L1 file count.** TidesDB's L1 holds flush outputs that may overlap, so its file count is direct
  read amplification and wants an explicit bound.
- **Tombstone density.** A delete-heavy family whose levels are not growing would never compact
  under a capacity-only rule, and its tombstones would keep costing space and read work.

**Per-family policy.** Every column family runs its own instance with its own triggers.

### Where TidesDB diverges

**The SSD garbage-collection model is adopted in part.** Part of Spooky's motivation is that flash
devices lay data out across erase units, so files of differing lifetimes becoming interspersed
makes device-level garbage collection rewrite data repeatedly. Spooky's design deliberately caps the number of files being written
simultaneously at three — one from the buffer flush, one from a full preemptive merge, one from a
partitioned merge — and merges file pairs *in key order* so data is written and discarded in the
same order.

TidesDB keeps the second of those. A partitioned merge is a single streaming pass that rolls to a
new output at a boundary as keys go by, so within a job outputs are written in key order with one
file open at a time. It does not impose the global cap: flush and compaction are sized
independently and may have several outputs open across jobs.

That is a deliberate trade of device-layout tidiness for parallelism, and it is settled rather than
outstanding: the cap addresses garbage collection inside the device, and on the storage TidesDB has
been characterised against, device-level amplification does not vary with the number of files being
written at once. The parallelism it would cost is real and measured; the amplification it would
save is not detectable. The flush build in particular was parallelised with an ordered install for
exactly that throughput reason.

**The output size cap, adapted for separated values.** The paper splits an output whose projected
size exceeds `N_L / T`. TidesDB applies that rule, derived from the same quantities, on top of
boundary alignment rather than instead of it — so a partitioned merge caps each partition's output
too.

The adaptation is in what gets counted. The paper has no key/value separation, so an output's size
and its data volume are the same quantity. Under separation they are not: a spilled value leaves
only a reference in the klog, and what a later merge rewrites is the klog alone. So the cap counts
klog bytes. Counting logical value bytes instead would split a run of large values into one file
per key while the files it produced were tiny.

The cap also has a floor: a computed cap below one mebibyte is reported as no cap at all. On a
small or barely-populated tree `N_L / T` can fall to a few kilobytes, and honouring that literally
would roll a new file every few keys — paying a file's worth of overhead to bound something that
was never large.

What TidesDB does not implement is the paper's **seamless adaptation** — re-splitting a file that
skewed deletes have left larger than the current maximum. The cap applies when a file is written,
not retroactively to one already on disk.

## WiscKey, and what TidesDB takes from it

WiscKey's observation is that LSM compaction rewrites values repeatedly even though only keys need
sorting. Separating them means compaction moves keys only, so write amplification collapses for
large values.

TidesDB takes the core idea: values at or above the database's `value_separation_threshold` are
written to a value log, and the key log stores a reference.

It also takes WiscKey's second observation, which is the one about the write-ahead log. **The value
log is written by the committing transaction, not by the flush.** A large value written inline would
reach the device twice — once in the log record and again in the sstable the flush builds — so the
commit puts the bytes in the value log and the record carries only the id. On a 4 KiB-value workload
that is the difference between a write amplification of 2.10 and 1.06, and it is also why a memtable
of large values holds far more keys before it fills: a version costs an id rather than a value.

It also inherits the cost, and the manual says so where it matters — a point read of a separated
value costs a second I/O, and a scan that dereferences values pays it per entry.

### Where TidesDB diverges, and this is the substantive part

**Values are addressed by opaque logical id, not by file offset.**

This is the important difference. In WiscKey a value's address *is* its position in the vLog, so
garbage collection — which appends surviving values back to the head — must update the LSM entry
for every value it moves. Reclaiming space writes to the tree.

TidesDB stores a logical id. An id names one block for its whole life, so **ordinary compaction
carries a value forward by id without reading, re-encoding, or moving it**, and reclaiming a segment
that nothing references rewrites no tree at all. The indirection costs an id lookup on read and buys
a reclamation whose common case touches only the value log.

**Liveness has three holders, not one.** Because the commit writes the value, it exists before any
tree names it, and it stays that way until the memtable holding the reference is flushed. So the
live set is not the installed tables alone: a memtable and an undecided prepared batch hold
references too. Tables and prepared batches are counted; memtables are covered by a floor, since
their contents move under a reader. Getting that wrong is not a space leak but data loss, and each
of the three was found that way.

**The key is not stored beside the value.** WiscKey stores `(key size, value size, key, value)` in
the vLog specifically so garbage collection can determine validity by querying the LSM with the key
it just read from the tail. TidesDB does not need the key, and does not need to read the value log
to decide validity either: **every sstable records which segments its separated values landed in and
how many bytes of each it holds**, in its footer. Summed over the installed tables, that is the live
bytes of every segment exactly, computed from metadata alone.

That is the substantive divergence. WiscKey §3.3.2 dismisses scan-based collection as "too
heavyweight and only usable for offline garbage collection", and it is right: TidesDB first tried
asking the engine for the live id set, which meant scanning every key of every sstable of every
family on one shared store, and on a database large enough to need reclaiming that scan does not
finish. Making the trees *report* what they hold instead of being *read* is what removed the scan.

**Two tiers over sealed segments, not a head/tail circular log.** WiscKey keeps valid values in a
contiguous range between a tail and a head, reading a chunk from the tail, re-appending survivors to
the head, and advancing the tail. TidesDB's store is a series of numbered segments, and it never
copies a value itself. A segment nothing references is unlinked whole. A segment holding little
enough live data is *marked*, and the next compaction that carries one of its values forward writes
that value afresh instead of keeping the reference — so the segment empties through a merge that was
already scheduled, and is then unlinked for free.

This is closer to RocksDB's blob garbage collection than to WiscKey's: the rewriting happens inside
compaction, where a table is being rebuilt anyway, rather than in a separate pass that must move
bytes underneath live readers. What a reclaim leaves behind is a whole file gone rather than a
boundary advanced, so there is no partially-reclaimed region to reason about, and because nothing is
ever copied within the store, a crash cannot leave the same id in two places.

**One database-wide value log, not one per store.** Every column family shares it. Per-family logs
would shrink the old scan, which is why they were considered — but the scan is gone, and liveness is
now metadata a shared store answers as cheaply as a split one would, at fewer files.

**No parallel value prefetching.** WiscKey's answer to slow range queries is to exploit SSD
parallelism: track the iterator's access pattern and prefetch values from the vLog with multiple
threads. TidesDB has no such prefetcher. Its mitigation is different in kind — key-only iteration
never dereferences a value at all, so a scan built on `tidesdb_iter_key` avoids the cost rather
than hiding it, as does an existence check through `tidesdb_txn_contains`. For a scan that genuinely needs every value, WiscKey's
prefetching would help and TidesDB does not have it.

**Values are encoded in the log, and each describes its own encoding.** A value block carries the
id, the uncompressed length, the chain of encoding ids the value was written through, and then the
stored bytes. The self-description is required rather than decorative: compaction carries a value
forward by id without re-encoding it, so the sstable referencing a value may record a different
pipeline than the one that wrote it, and one shared store holds values from families configured
differently.

## Aether, and the write path

Aether's contribution is that a log's scalability bottleneck is contention on log-space allocation
and the serialization of many small writes. Its answers are a consolidation array, so committers
combine their space requests, and flush pipelining, so filling and writing overlap.

TidesDB's buffered append ring is that shape: one atomic reservation, parallel fill by each
appender into its own slice, and a single flush thread draining the contiguous completed run. The
ring's allocation *is* the consolidation, and the flush thread *is* the pipelining.

The divergence is that TidesDB does not implement a consolidation array as a separate structure.
The ring's single reserving atomic already serves that purpose, and measurement found no remaining
allocation contention to remove.

## What is novel here

Not every part of TidesDB traces to a paper. The combination that does not:

**An LSM of B+trees with key/value separation.** WiscKey separates values from a conventional
LSM whose runs are sorted blocks with a sparse index. TidesDB's key log *is* a B+tree — the sorted
store and the index are the same structure, leaves are doubly linked for bidirectional scans, and
MVCC version resolution happens natively during the descent rather than as a filter above it.

Composing that with value separation has a compounding effect the papers do not describe. B+tree
node density is governed by entry size; moving large values out makes nodes hold far more keys,
which shortens the tree and raises cache hit rates for the nodes that remain. Value separation
helps a B+tree-based run more than it helps a block-based one, because it improves the index
structure itself rather than only the bytes rewritten by compaction.

**MVCC inside the run structure.** Versions live in the B+tree as version chains resolved against
a snapshot ceiling during the descent. Neither paper addresses multi-version visibility; both
assume a single current value per key.

**Logical-id indirection for reclamation**, described above, which makes value log compaction
independent of the trees that reference it.

These are design claims, not measured ones. The engine has not been evaluated against the papers'
benchmarks, and no claim here should be read as a reproduction of their results.
