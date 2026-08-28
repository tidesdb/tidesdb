---
title: Iterators and the Merge
description: One bidirectional k-way merge serving both user scans and compaction, and why a direction change is the hard case.
slug: internals/iterators
part: internals
sidebar:
  order: 14
---

# Iterators and the Merge

## The problem

A key's versions are scattered: some in the active memtable, some in sealed ones, some across
several sstables at different levels. A scan has to present them as **one ordered stream of the
newest visible version per key**, in either direction, without materialising anything.

This is the same problem compaction solves. A merge reads several sorted sources and resolves
each key to what survives — which is a scan whose output happens to be written to a file.

So there is one implementation. The merge is generic over a small source interface, and both
user iterators and compaction compose it. What they share is the hard part — keeping many sources
positioned, picking the next key across them, and reversing direction correctly — so the ordering
cannot diverge between a read and a merge.

What they do not share is what happens to the versions once ordered. A read resolves them against
its snapshot; a compaction takes the raw stream and applies its own retention. That split is the
subject of the next section.

## The source interface

A source is a small bidirectional cursor over a sorted, versioned key stream:

```
  first / last          position at either end
  next / prev           step
  seek / seek_for_prev  position at the first key >= / last key <= a target
  valid                 is it positioned
  get                   the entry at the position
```

Entries are byte-ordered by key, and several versions of one key appear adjacent. A memtable
adapter and an sstable adapter implement this; so do stub streams in the tests, which is why the
merge is testable with neither a memtable nor an sstable in existence.

The contract that matters: **the key and value a `get` returns are valid only until the next
positioning call on that source.** The merge copies what it needs before moving on. A caller
that held a returned pointer across a step would read freed or reused memory.

## Folding

The merge keeps every source positioned and repeatedly picks the smallest key among them
(largest, going backwards). All sources sitting on that key contribute versions, and the merge
resolves them to the **newest version at or below the snapshot**, discarding the rest.

Then the outcome depends on what that newest version is:

- A **live value** is emitted.
- An **expired** entry is treated as absent.
- A **tombstone** hides the key — *unless* the iterator was built to emit tombstones.
- A **covering range delete** hides the key too, when it is newer than the version the merge
  resolved. An interval sitting in one source has to hide a key that arrived from another, so every
  source is asked, not only the one the key came from. It is asked *inside* the merge rather than
  after it, which is what keeps the sources a scan reads and the intervals it honours the same set —
  applying the check outside meant two views of the store that could disagree, and a key the scan
  showed while a point read correctly hid it.

All of that describes a **read** scan, which is what snapshot resolution is for. A compaction does
not want any of it, and does not merely flip the tombstone switch — it asks for a **raw** merge
instead, which yields every version of every key, key ascending and then sequence descending, with
no snapshot applied and nothing hidden.

The reason is that a compaction is not answering a question at one point in time. It decides which
versions to keep against the oldest snapshot any live reader holds, and it must see the whole
version chain to do it. It must also write tombstones into its output, because a tombstone is what
shadows older versions in deeper levels the merge did not include — a compaction that dropped one
would resurrect the deleted key on disk. So retention and tombstone collection are the compaction's
own, applied to the raw stream; the merge supplies the ordering and nothing more.

A raw scan runs in one direction and **refuses to turn round**. The re-seek a resolving flip uses
resumes one step past the current key, stepping over that key's remaining versions — which is what a
read wants and exactly what a raw scan exists to see. Turning without one is no better: the sources
sit one step past the version just emitted, so the first step back re-emits it. Neither answer is
right, so `merge_iter_prev` on a forward raw scan returns `TDB_ERR_INVALID_ARGS` rather than a
silently repeated version. A raw scan that runs backward from the start never turns and is fine.

Range deletes are the exception to that division of labour: they never enter the merge stream at
all, in either mode. They live in the manifest, so a compaction asks the family whether an interval
covers each key it is about to emit rather than carrying tombstones through its output.

## Which sources the merge is built from

Every source the merge holds is a source it descends on each seek and compares on each advance, so
the cost of a scan is set by how many it has, not by how many keys it returns. An unbounded iterator
takes every sstable in the family — correct, and right for a full scan.

A scan that knows its range takes only the sstables whose own key range meets it. Each sstable
records its minimum and maximum key, so a level can be asked which of its files overlap a range and
the rest are never opened at all. A narrow scan of a family holding hundreds of sstables then costs
a handful of descents instead of hundreds, and concurrent narrow scans stop competing for the whole
store at once. Measured on a family of 32 disjoint sstables, a four-key scan went from 128 block
cache lookups to 4.

:::caution[A short scan is dominated by what it opens, not by what it reads]
Building the merge opens a cursor into every source it kept, and each sstable cursor descends that
tree from its root. So the setup is proportional to how many runs overlap the range, while the
payoff is proportional to the rows returned — and a lookup that returns a handful of rows pays the
whole setup for them. That ratio, not the per-row cost, is what makes a secondary-index lookup
expensive on a family with many overlapping runs, and it is why pruning matters more for short
scans than for long ones.

It is also why L1 is the tier that hurts. Its files may overlap and, when written from a memtable
holding interleaved writes, each one spans the whole key space — so the range check cannot exclude
any of them and every scan opens every L1 file whatever range it asked for.

Measured, on a store under live write load, a short index lookup spends roughly **a third of its
cycles before it reads an entry at all**: the range prune that picks the sources, the refcount taken
on each sstable it kept, and the pin on the active memtable. The prune itself is not a scan of the
level — deeper levels are binary-searched — the cost is that it is paid once per level per lookup,
along with the epoch enter and exit that make the layout safe to read.
:::

The bound is a **contract, not a fence**: the iterator's results are defined only inside the range
it was given, because the sources that could answer outside it were never opened. A caller that
seeks past its own bound is asking a question the iterator was not built to answer.

## Direction changes

This is the hard case, and the one most such implementations get wrong.

While iterating forward, a source that runs out is exhausted and drops out of consideration.
Reversing does not simply flip the comparison: an exhausted source may hold entries *behind* the
current position, and it is no longer positioned anywhere useful. Sources that were never
exhausted are positioned one step past what the merge last emitted, which is the wrong place to
step backwards from.

So a direction change **re-seeks every source around the current key** rather than trying to
reverse in place. It costs a seek per source, and it is the reason the reference
[warns that flipping repeatedly is not free](/reference/iterator#direction-changes-are-supported-but-not-free).

The property being bought is that a flip never drops an entry and never repeats one — which is
worth a seek, since both failure modes are silent.

## Stability

An iterator reads at a fixed snapshot, so its view does not change while it runs even as other
threads commit, flush, and compact.

Which snapshot depends on the isolation level, and it is the same one a point read in the same
transaction resolves against — `txn_read_snapshot`, not the begin sequence unconditionally.
Repeatable-read, snapshot and serializable transactions carry a snapshot drawn at begin and the
iterator reads at that, so every scan in the transaction sees one instant. A read-committed
transaction holds no such snapshot, so the iterator draws the current sequence when it is created:
it sees everything committed before it started, and successive scans in one transaction can
legitimately differ. Read-uncommitted reads at the maximum sequence, which is what makes another
transaction's uncommitted versions visible to it.

Reaching for the begin sequence directly would be wrong rather than merely coarse: a
read-committed transaction has none, and filtering a scan against it would hide every live row.

Over that committed view the scan folds the transaction's **own buffered writes**: its uncommitted
puts appear, and its deletes hide the rows beneath them, exactly as point reads resolve them
through the write set.

Making that true requires holding things alive. An iterator's sources pin what they read: memtables
by epoch or reference count, sstables by the reference their level-set layout holds. A compaction
may replace a layout while an iterator is inside the old one; the tables it is using are freed only
when it lets go.

The cost is that a long-lived iterator holds back reclamation — sstables it pins cannot be deleted,
and the transaction behind it holds `min_snapshot_seq` down. A scan left open across a long
operation is a real source of space that will not reclaim.

A transaction timeout bounds the second half of that but not the first. Expiry is lazy, so it
resolves the transaction at its next operation and releases the snapshot; the iterator's own pins
last until it is freed, whatever the transaction behind it did.

## Where the value comes from

The merge yields keys and, for entries whose value is inline, values. A value above the family's
threshold lives in the value log, and it is dereferenced **only when asked for**.

That is why a key-only scan is dramatically cheaper than a key-and-value scan over separated
values, and why [`tidesdb_iter_key`](/reference/iterator#tidesdb_iter_key) and
[`tidesdb_iter_value`](/reference/iterator#tidesdb_iter_value) are separate calls rather than one
that always returns both.

## Invariants

| Invariant | Why |
| --- | --- |
| One merge serves reads and compaction | The ordering and direction handling must not diverge between them |
| A raw scan runs in one direction only | `test_merge_raw_refuses_a_direction_flip` — the resolving flip's re-seek steps over the versions raw exists to emit, and turning without one re-emits the version just delivered; a raw flip is refused rather than answered wrongly |
| A source's returned key/value dies at the next positioning call | The merge copies before stepping; callers must not hold it |
| A read resolves against its snapshot; a compaction reads raw | A compaction decides retention across the whole version chain, which a resolved stream has already discarded |
| A compaction writes tombstones to its output | They shadow older versions in levels the merge did not include; dropping one resurrects the deleted key |
| A direction change re-seeks every source | Exhausted sources hold entries behind the position |
| Sources stay pinned for the iterator's life | A compaction may replace a layout mid-scan |
| A bounded iterator answers only inside its bounds | Sources outside the range were never opened, so a key beyond it may have no source that holds it |
| The snapshot is fixed for the iterator's life | Stability is the guarantee an iterator makes; which snapshot it is comes from the isolation level, but it does not move once chosen |
