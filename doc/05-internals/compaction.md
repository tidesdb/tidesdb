---
title: Compaction
description: Spooky -- a pure deterministic planner, the jobs it emits, and the executor that merges them.
slug: internals/compaction
part: internals
sidebar:
  order: 9
---

# Compaction

## The problem

Flushing produces a file per sealed memtable, all in L1, all potentially covering the same key
range. Left alone, a point lookup would have to consult every one of them, and read
amplification would grow without bound. Compaction merges files into fewer, larger, deeper
ones so that reads stay cheap.

Every LSM engine faces the same three-way trade. Merge aggressively and reads are fast but
write amplification is high. Merge lazily and writes are cheap but reads consult many files.
Compaction *policy* is where an engine picks its point on that curve, and it is the single
biggest determinant of behaviour under load. TidesDB follows a published design here rather than
an ad-hoc one, which is what makes the policy separable and testable.

## The planner is a pure function

TidesDB's policy follows **Spooky** (Dayan et al., PVLDB 2022) — see
[Design lineage](/internals/design-lineage) for what is implemented as published and what
diverges — and separates the decision-making completely from the doing.

The planner is given a snapshot — the byte size and file count of each level, plus the
family's configuration — and returns decisions. It performs **no I/O, opens no files, reads no
clock, and touches no handles**. The same snapshot always produces the same plan.

That is not stylistic. Compaction policy is the hardest part of an LSM engine to get right and
the hardest to test, because in most implementations it is entangled with the I/O it schedules.
Here it is tested by handing it numbers and checking the answer, so its behaviour at level
counts and size distributions that would be painful to construct on disk is trivially
exercised.

## Level capacities: DCA

Levels are 1-based. The classic scheme gives level *i* a capacity of `base × T^(i-1)` for a
size ratio `T` — a geometric series fixed in advance.

Spooky pairs with **DCA — Dynamic Capacity Adaptation**, introduced by RocksDB and adopted by
the paper — which sizes the smaller levels relative to *how much data the largest level actually
holds*:

```
  C_L  = base × T^(L-1)              the largest level keeps a geometric capacity
  C_i  = N_L / T^(L-i)   for i < L   a smaller level is a fraction of the largest level's data
```

where `N_L` is the current byte size of the largest level. The consequence is that capacities
**adapt to the data**. A database that is half full does not carry the level capacities of one
that is full; the intermediate levels stay proportionally small, so the work of maintaining
them stays proportional too.

## The dividing level

```
  X = num_levels - 1 - dividing_level_offset      clamped to [1, num_levels - 1]
```

A tree with fewer than two levels has no dividing level at all and yields 0, since there is
nothing below to partition against.

`X` is the shallowest level whose merges **partition their output** by the largest level's file
boundaries, instead of writing one output file.

The reason is the cost of merging into a large level. A merge that produces one enormous file
must rewrite it in full next time anything overlaps it. By splitting output at the boundaries
of the level below, each subsequent merge touches only the partitions it actually overlaps.
`dividing_level_offset` moves that behaviour shallower or deeper — shallower partitions sooner
and keeps individual merges smaller; deeper defers the bookkeeping.

It **defaults to 1**, putting `X` at `L − 2`. Spooky measures both ends of this: at `L − 1` a
dividing merge rewrites a level holding a tenth of the data in one go and the system runs out of
space at scale, while at `L − 4` it exhausts the open-file budget. `L − 2` is the balance, and it
also keeps output files large enough to be written as long sequential runs.

## The tree grows with the data

A family starts at one level and gains levels as it fills. When a merge would land in the largest
level and that level is already at its capacity, it lands one level deeper instead — which is how a
level is added. The count settles near `log_T(N/B)`, and the capacities above are what bound the
space that costs.

The step is easy to leave out and expensive to omit. Without it a family stops deepening, so every
merge has to land in a level it already occupies, the dividing level collapses onto the flush tier,
and the tier grows one run per flush with nowhere to drain to. Every trigger still fires, every plan
still produces jobs, every job still succeeds — and a scan of any range still ends up opening every
run in the tier. Growth is evaluated where the target is chosen, **after** a merge has been selected
rather than before, so it cannot preempt a dividing merge that was already due.

## Partitioned merges fan out when their inputs allow it

Spooky's partitioned merge compacts **one group of perfectly overlapping files at a time** across
the largest levels. When every input in the merge range sits wholly inside one of the largest
level's boundary partitions, the plan emits **one job per partition**. Those jobs share no input, so
they may run at the same time, and each costs one partition of transient space rather than the whole
span of levels it covers.

That is only sound when the inputs really are aligned, and the plan checks rather than assumes it.
The largest level is partitioned to these boundaries by construction, and a dividing merge writes
its output the same way — so alignment holds once the levels above have been through one. But a run
flushed straight into the tier spans whatever its memtable happened to hold, which under interleaved
writers is the entire key space.

:::caution[A spanning input forces one job]
If any input straddles a boundary, the merge stays a single job over the whole range. Per-partition
jobs would then share that input, and because the executor removes a job's inputs **atomically**,
only the first could run — the rest would find the shared input gone and skip. A largest-level
tombstone would be dropped without the older versions it shadows, and the deleted key would come
back.
:::

## A lone job splits its range across threads instead

The tier drain is exactly the case above: a file flushed into the tier spans the key space, so the
plan cannot divide it and emits one job. Left there, one thread carries the whole drain for the
family, and a family that cannot drain accumulates overlapping runs that every read then pays for.
Adding compaction threads does not help, because there is no second job for them to take.

So the executor divides what the planner could not. **A job that is the only one in its plan splits
its key range at the same boundaries its output would have rolled at**, and runs those ranges on
separate threads.

The output is the same either way. That single job already carries the boundaries and already seals
its current file whenever a key crosses into the next partition — it was producing one file per
partition all along, one after another. Handing each thread a contiguous run of those partitions
produces the same files; what changes is that several are built at once.

Two properties make the split safe. The merge holds no state across keys — the base-version decision
resets on every new key, and tombstone collection is a per-key question — so ranges are independent.
And the split keys are real keys from the level above with an exclusive upper bound, so every version
of a key stays in one range and retention sees a whole version chain exactly as one pass would.

The inputs are shared, immutable and already referenced; each range opens its own cursors over them.
Resolution and commit stay single, which is what keeps a stale job a no-op and the install atomic.

:::note[It applies to one job, not to every job]
A plan that emitted several jobs is already spread across the pool, and letting each of those
subdivide as well would multiply the thread count by the partition count. Only a plan that produced
a single job permits it. Measured on a sustained single-family fill, this took compaction throughput
from 1.27x to 1.93x across one to four threads, and the compactions completed per minute from 15-16
to 20-21 — the count being the drain-rate signal, since it was previously pinned regardless of how
many threads the family was given.
:::

:::caution[It raises the load a family can carry, not the depth it carries a load at]
Read amplification is an equilibrium: the flush tier grows when data arrives faster than compaction
takes it away, and settles where those rates meet. Draining faster does not make a load the family
already keeps up with any shallower — it raises the load at which it stops keeping up.

Measured at a pinned input rate, with the split as the only variable: at a rate both sustain the two
are indistinguishable, same depth and the same level shape. Between the old drain ceiling and the new
one, the divided merge reaches the target where the undivided one falls short, and writers spend a
third of the time parked — at the *same* read amplification. Past both ceilings neither keeps up.

So the benefit to a read is indirect. Depth grows when a family cannot drain, and this moves the
point where that starts.
:::

## And sheds one when the data goes away

The reverse also happens. When the largest level has shrunk to less than a size ratio's worth of its
own capacity, that level is merged into the one above it and the tree loses a level.

The two thresholds are deliberately far apart — growth at the capacity, shrink at a `T`-th of it —
and that gap is hysteresis. A family sitting near a boundary would otherwise grow and shed the same
level repeatedly, paying a full merge each time.

Shedding is judged **on its own**, not behind the backlog triggers. A family whose data was mostly
deleted has no level at capacity and no tier over its file count, which is exactly the state an
over-deep tree would otherwise be stuck in forever, with every read paying for levels that hold
almost nothing.

The merge takes **both** the largest level and the one it lands in. Levels below the flush tier hold
non-overlapping runs, so moving the deepest level's files into a level that already holds files
would leave two overlapping runs at one level and a read there would have to consult both.

`min_levels` is the floor: a family already at its configured minimum depth stays there however
little its largest level holds. The engine's own floor is a flush tier plus one level for merges to
land in, since below that the dividing level has nowhere to sit.

## What makes a merge due

Three triggers, checked against the snapshot:

| Trigger | Condition |
| --- | --- |
| **L1 file count** | L1 holds at least `l1_file_count_trigger` files |
| **Level capacity** | Some level's size has reached its DCA capacity |
| **Tombstone density** | An sstable's tombstone fraction has reached `tombstone_density_trigger`, above a minimum entry count |

The L1 trigger is the read-amplification guard: L1 files overlap, so every one of them is a
file a point lookup may have to consult. The capacity triggers keep the shape of the tree. The
tombstone trigger exists because deleted data costs space and read work until a merge can
prove it is safe to drop — a family that is mostly deletes would otherwise never compact, since
its levels are not growing.

A forced [`tidesdb_compact`](/reference/maintenance#tidesdb_compact) sets `force`, which plans a
merge whether or not a trigger is due.

### When the scheduler decides not to look

Planning a family means referencing every sstable it owns and copying their metadata. Doing that
once a second for every family costs more as the database grows and usually produces the plan it
produced last time, so the scheduler memoizes: it skips a family whose **level-set generation** and
**reclamation floor** both match what it last planned against.

Both inputs are needed, and the second is the one that is easy to omit. A merge's value does not
come only from the shape — when the last long-running transaction ends, `min_snapshot_seq` rises and
versions the same layout could not drop become droppable. Keyed on shape alone, the scheduler stops
reconsidering a family at exactly the moment the work becomes worth doing, and on an idle database
nothing ever moves the shape again.

The memo is recorded **only when the plan came back empty**. A plan that produced jobs is left
unrecorded on purpose: if the jobs run, the layout moves and the memo would not have applied anyway,
and if they fail the layout does not move — so recording it there would retire the family from
scheduling until something else happened to write to it. A single failed compaction would otherwise
stop that family compacting for the life of the process.

### The merge target is never the flush tier

Spooky's preemptive merge picks the smallest level that could hold everything at and below it, and
folds the smaller levels into it. TidesDB numbers the flush tier **L1**, so that search has to start
at **L2**: a merge whose target is L1 reads the tier and writes it straight back, consolidating its
files while leaving every byte exactly where it was.

That distinction is not academic. L1 is where every flush lands, one run per flush per family, so a
merge that does not promote leaves the tier growing at the arrival rate no matter how often it runs.
Every trigger fires, every plan produces jobs, every job succeeds — and the tier still climbs to
dozens of runs, each spanning the whole key space, until some other path happens to promote it.
A scan of any range then opens all of them, which is the read-side collapse reached without a single
component failing.

The tier is always an **input** to a merge and never its destination.

## Jobs

The planner emits **jobs**. Each job is a merge unit: its input sstable ids, its target level,
and how to split the output.

| Split policy | Behaviour |
| --- | --- |
| `COMPACTION_SPLIT_NONE` | Outputs are not aligned to anything — the target is below the dividing level |
| `COMPACTION_SPLIT_BOUNDARIES` | Roll at the largest level's file boundaries — the target *is* the dividing level, or the job is a partitioned merge |

Independently of alignment, a job carries a **size cap**. An output rolls once it reaches that many
klog bytes, so a partition holding an unusually large share of the data does not yield one
correspondingly large file that every later merge touching it must rewrite.

The cap is derived as a fraction of the largest level's data, so it tracks the tree rather than
being a fixed number, and it is not applied at all while that fraction would be too small to be
meaningful — a young tree would otherwise split every entry into its own file.

:::note[The cap counts the klog, not the data]
With values separated, a spilled value leaves only a reference in the klog. The cap therefore
counts what the klog actually holds, because what a later merge rewrites is the klog — the values
stay where they are. Counting logical value bytes would split a run of large values into one file
per key.
:::

Splitting a job into per-partition sub-merges is what keeps individual merges bounded. It is
also where a subtle correctness hazard lives, discussed below.

## The executor

The executor takes a job and does the I/O. It reads its inputs through the **same k-way merge
iterator that serves user iterators**, but asks it for a **raw** stream: every version of every
key, ordered by key and then by sequence descending, with no snapshot applied and nothing hidden.
What the two share is the hard part — keeping many sources positioned and picking the next key
across them — not the resolution, which a compaction has to do for itself because it decides
retention across the whole version chain rather than answering at one instant. See
[Iterators](/internals/iterators).

For each key it decides what survives:

- The **newest version** always survives.
- **Older versions** are dropped once no live snapshot could still need them. The floor is the
  oldest snapshot any live transaction holds, exposed as `min_snapshot_seq`. A long-running
  transaction holds that floor down and keeps garbage alive — a real operational effect, and
  the reason a forgotten open transaction shows up as space that will not reclaim.
- **Expired entries** are dropped.
- **Versions a range tombstone covers** are dropped once that tombstone sits at or below the floor,
  the base version included — nothing can resolve to it any more. See below.
- **Tombstones** are the hard case.

### Range tombstones, which the sstables carry

A [range delete](/reference/transaction#tidesdb_txn_delete_range) lives in the table the memtable
holding it flushed into, in a block of that table's own. A merge unions what its inputs carried into
its outputs, so an interval travels down with the data it deletes and its lifetime is a table's
lifetime. A family reached only by a delete still gets a table for it, holding the interval and no
keys, which is what gives the delete somewhere to live.

There is no separate store to keep in step and nothing to prove spent. An interval is present
exactly while some table carries it and goes when the last table holding it is merged away.

That property is what an earlier design failed to get right. Keeping intervals in a store of their
own meant deciding when one had nothing left to hide, and the answer had to hold across every table,
every unflushed memtable and every unreplayed log at once. A per-table watermark cannot carry that
claim: intervals reach a family in flush order rather than in sequence order, so a table asserting
it applied everything through a sequence can be handed one beneath that mark afterwards. Every key
such an interval covered came back.

### Where an interval stops travelling

Carried forward unconditionally, intervals would only ever accumulate — every merge writing the
union of what it read, for as long as the family lives. One merge can end that, and only under
three conditions together:

- It is writing the **largest level**, so there is no level below holding an older version.
- The interval's sequence is at or **below the reclamation floor**, which is what says every reader
  that can still exist already sees it applied — and is the same ceiling the per-entry drop above
  ran under, so this merge really did delete what the interval covered rather than carry it past.
- **No sstable outside the merge reaches into its range.** A key it covers that this merge never
  read is a key that comes back the moment the interval stops being carried.

Together those say the merge has just done the last of the interval's work, so its outputs are
written without it. The test that pins the drop and the test that pins the carry are the same pair:
`test_cf_source_compaction_drops_an_interval_it_has_finished` and
`test_cf_source_compaction_carries_input_intervals`, the second of which leaves a table outside the
merge holding a covered key precisely so the interval must survive.

Everything here is one-sided in the safe direction. A level the scan could not read, a level with
more overlapping tables than it will inspect, an unbounded upper bound, and a table beginning
exactly at the interval's exclusive end all count as reaching in. Each keeps an interval that could
have gone, which costs space; the other error loses data.

### Why tombstones are hard

A tombstone must be retained until the merge can prove that no older version of that key
survives *beneath* it. Drop it while an older value still exists in a deeper level, and that
value becomes visible again — the delete is undone.

So a tombstone may only be dropped when the merge includes **every sstable that could hold the
key**. If the merge covers a subset, the tombstone is written to the output and lives on.

This interacts directly with partitioned merges. A partitioned sub-merge sees only part of the
keyspace, so its notion of "every sstable holding this key" has to be evaluated over the
*whole* boundary-split job rather than the sub-range in front of it. Getting that wrong
resurrects deleted data, and it is subtle precisely because each sub-merge looks locally
correct.

The proof has to fail closed. The check asks each level which sstables overlap the key, into a
fixed-size array, and a level that reports more than fits leaves a sibling it never examined —
so that case refuses the drop rather than concluding from what it did see. A level it could not
read at all refuses too. The tombstone surviving a merge it could have left costs one entry; the
opposite mistake costs a resurrected key.

A **single-delete** is the exception: the caller has promised the key was written at most once,
so the tombstone and that one put annihilate as soon as a merge sees them together. That
promise is unverifiable by the engine, which is why breaking it resurrects data.

### A lapsed entry arrives as a tombstone

An entry whose deadline has passed is read as a tombstone rather than as a value, and the merge
reads its inputs through that same path — so expiry needs no rule of its own here. A lapsed entry
enters the merge already a tombstone, shadows older versions of its key exactly as a delete would,
and is collected on precisely the terms above: dropped once the merge can prove nothing older
survives beneath it, retained otherwise. It is written out without a deadline, since a tombstone
has nothing left to outlive.

This is why the read path hides a lapsed entry rather than skipping it. Skipping would leave the
older version underneath reachable, and no merge would ever be asked to collect anything.

## Concurrency

A family carries a claim, taken for a whole **plan** and released when the last of its jobs
returns. So only one plan runs on a family at a time — but the jobs that plan emitted run
concurrently, on separate workers, which is exactly what the per-partition fan-out above is for.
The claim is what [`tidesdb_compact`](/reference/maintenance#tidesdb_compact) reports as
`TDB_ERR_LOCKED`, and what a runtime configuration change contends with — the scheduler must not
read the planner knobs while they are being replaced.

Outputs and input removals commit to the manifest in **one batch**, so the set never contains
both the inputs and their replacement, nor neither. Readers already inside a replaced sstable
are safe: the level set's layout holds a reference on every table in it, so a table is freed
only when the last reader leaves.

### Reclaiming the merged-away inputs

Dropping an input from the catalogue and the level set stops anything reading it, but the
filesystem is still charged for the file until someone unlinks it. Those are separate acts, and
the gap between them is deliberate.

The unlink cannot happen at commit, because a reader may still be inside the file. It also must
not happen *before* the commit: a crash in between would leave the manifest naming a file that is
gone, and outside L1 — where the data can be replayed from the write-ahead log — that fails the
next open outright rather than self-healing.

So each input is **marked** once the swap is published, and the unlink happens where both
conditions are already satisfied: when the last reference to that sstable drops. That is the same
moment the handle is closed, and by then the manifest edit has committed and no reader is left.

The mark waits for the swap rather than riding on the commit, because a swap that cannot be
published leaves the inputs as the live data — still installed, still the only copy anything can
read. Marking them at the commit would send their files with them the moment the level set let go,
for a merge whose result nothing ever adopted.

A swap that fails after the commit is rolled back rather than left: the inputs are named again at
the levels they were removed from and the outputs are withdrawn, so the catalogue matches what is
installed. Without it the catalogue keeps naming outputs no level set took, and the next merge of
the same inputs names a second set — which a reopen then adopts alongside the first.

Skipping the mark does not corrupt anything and nothing reads the leftover files — which is
exactly why it is easy to miss. What it does is grow the store without bound for as long as the
database stays open, while the level set goes on reporting a healthy live set, because every
round of compaction rewrites its data and keeps the previous copy.

## Invariants

| Invariant | Why |
| --- | --- |
| The planner performs no I/O and reads no clock | Determinism is what makes policy testable |
| Versions are dropped only below `min_snapshot_seq` | A live snapshot must still see what it could see |
| A tombstone drops only when every sstable holding the key is in the merge | Otherwise a deeper value is resurrected |
| Tombstone safety is evaluated over the whole job, not a sub-range | A partitioned sub-merge sees only part of the keyspace |
| Outputs and removals commit in one manifest batch | The set must never hold both or neither |
| A merged-away input is unlinked when its last reference drops | Earlier and a reader is still inside it, or a crash leaves the manifest naming a missing file; never, and the store grows without bound while the live set looks healthy |
| An input is marked for unlink only once the swap is published | A swap that could not be published leaves the inputs as the live data, and a mark taken at the commit would take their files the moment the level set let go |
| A commit the level set does not take is rolled back | Otherwise the catalogue names outputs nothing installed, and the next merge of the same inputs names a second set that a reopen adopts alongside them |
| One compaction **plan** per family at a time | The claim is taken for a whole plan and released when the last of its jobs returns, so two merges of one family do run at once -- on separate workers, over the plan's separate jobs. What it excludes is a second *plan*, and it also protects the config from a torn read |
| The plan memo is keyed on the shape and the reclamation floor together | A floor that rose makes versions droppable that the same layout could not drop, so shape alone stops reconsidering a family exactly when the work becomes worthwhile |
| A plan that produced jobs is never memoized | The jobs may fail, leaving the layout unmoved; memoizing there retires the family from scheduling until something else writes to it |
| Deeper is older | Merging must never place an older table above a newer one |
