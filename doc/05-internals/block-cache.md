---
title: Block Cache
description: One bounded pool behind the sstable read path, with lock-free reads and exactly-once payload reclamation.
slug: internals/block-cache
part: internals
sidebar:
  order: 10
---

# Block Cache

## The problem

Every read that misses memory reads a block from a file — a btree node, a filter partition, a
raw block on the sstable read path. Reading the same block repeatedly from the operating system
is wasteful, and the kernel's own page cache does not help as much as it looks: a btree node arrives as bytes and
has to be *parsed* before it is useful, and parsing it on every access is much of the cost.

So the engine keeps its own cache, and it caches **parsed objects as readily as raw bytes**.
The consequence is that a cache hit skips both the read and the parse.

## One cache, database-wide

:::note[The value log deliberately does not read through it]
The sstable read path uses this cache — btree nodes and filter partitions — and the value log does
not. A filter's *partitions* are cached; its routing *directory* is not, because every probe of that
table starts by consulting it and an evicted directory would have to be re-read and re-parsed before
the cache could even be asked. It is held by the sstable instead, outside this budget, and reported
as `filter_resident_bytes`. That is a deliberate choice, not an omission. The cache earns its budget on btree nodes
because it stores them **parsed**, so a hit skips real work; values are raw bytes the operating
system's own page cache already holds, and caching them a second time in the engine displaces the
nodes that make lookups fast. Keying is the other half: a value is reached through its logical id
rather than by position, and the segment holding it can be unlinked whole by a reclaim, so an entry
keyed by file offset would outlive the file it named.
:::

Not per family, not per sstable. One bounded pool shared by everything, because a per-file
cache would carve the memory budget by file rather than by usefulness — a hot family with few
files would be capped while a cold one with many held memory it was not using.

The key is `(file_id, offset)`: the 64-bit id of the owning file plus the block's byte offset.
Together those name one block unambiguously across the whole database, which is what lets one
pool serve every file without collisions.

## Structure

The cache is divided into independent **shards**, each with a fixed array of frames and a
bucket table mapping keys to them:

```
  shard 0   [ frame ][ frame ][ frame ] ...    +  bucket table  +  lock  +  clock hand
  shard 1   [ frame ][ frame ][ frame ] ...    +  bucket table  +  lock  +  clock hand
  ...
```

Sharding is what keeps writers from serializing: a put takes only its own shard's lock. The
shard count is derived from the CPU count and the frames per shard from the configured capacity,
both rounded to powers of two so the mapping is a mask rather than a division.

:::caution[The frame count must follow the byte budget]
A shard evicts on **bytes**, but it can only hold as many entries as it has **frames**. If the
frame count is capped below what the budget can hold, the frames run out first and the cache
plateaus at a fraction of its configured size — while still reporting the budget it was given. That
failure is silent and reads as a miss-rate problem rather than a sizing one: an eight gigabyte cache
capped at eight thousand frames per shard holds two gigabytes, and every read past that point misses
and evicts.

So the frame count is derived from the budget and not capped below it. The metadata a frame costs is
a fixed fraction of the entry it tracks — about two percent — so the array cannot grow out of
proportion to the budget it serves. How long an insert may hold the shard lock hunting a victim is a
**separate** limit, bounded absolutely rather than as a multiple of the frame count; conflating the
two is what produced the cap.
:::

:::caution[A frame is charged what it reserves, not what it uses]
A cached btree node is decoded into an **arena of its own**, and an arena serves its first request
by taking a whole chunk from the shared pool. So the memory a frame holds is the chunk, which is
rounded up, and not the bytes the node happened to need.

The budget is charged that reserved figure. Charging the used one — which is what the code did until
it was measured — let a shard hold several times the memory it had been given, and the overshoot was
invisible, because nothing reported the difference between the two. It was worst on a *small* cache,
where the rounding is largest relative to the budget: a 64 MiB cache was measured resident at 908
MiB, while a 1 GiB cache overshot by only a tenth. That shape is why it survived — the failure
shrinks exactly as the configuration grows, and the test that guards the budget uses entries near the
nominal size, where there is almost nothing to round.

The consequence to carry into sizing: **a byte of budget buys less than a byte of node data**, by
whatever the chunk rounds up. The pool's chunk is twice the node size a family is created with, so at
the default a frame holds about half its chunk in useful node bytes.

That ratio was once far worse. The chunk was derived from the btree builder's *fallback* node size —
the value used only when a caller asks for none — while families are created with a node size
sixteen times smaller. Every cached node then reserved a 128 KiB chunk to hold about 4 KiB, and a
256 MiB cache spent its whole budget on 2,007 frames holding 8 MiB of node data. Tying the chunk to
the size families actually use took the same budget to 31,677 frames, raised the hit rate from 0.90
to 0.98, and raised read throughput 35%. The lesson is not about the constant: **two numbers that
describe the same object have to be defined in terms of each other, or they drift and nothing
reports it.**
:::

Frames are **fixed and never freed** while the cache lives. That is the central design choice
and everything else follows from it: a reader that has found a frame can hold it without any
risk that the frame itself disappears. Only the *payload* a frame points at is ever reclaimed.

A frame is in one of three states:

| State | Meaning |
| --- | --- |
| `FREE` | Reusable |
| `LIVE` | Holds a gettable entry |
| `DYING` | Evicted, but still pinned by at least one reader |

`DYING` is what makes eviction non-blocking. An evictor does not wait for readers to leave; it
marks the frame and moves on, and the payload is released by whichever thread drops the last
reference.

## Reads are lock-free

A get takes no lock at all:

1. **Probe** the bucket chain for the key.
2. **Pin** the frame with an atomic reference count.
3. **Recheck** that the frame still holds the key that was probed.

The recheck is the whole trick. Between the probe and the pin, the frame may have been evicted
and reused for a different block. Pinning first and verifying second means a reader either ends
up holding what it asked for, or notices it does not and retries — and it never holds a
reference to something that has been freed, because frames are not freed.

Evicted keys leave a **tombstone** in the bucket table rather than a hole, so a removed key
cannot truncate the probe chain of a key that hashed past it.

### The probe stays inside the bucket table

A bucket is a single 32-bit word holding a frame index with an 8-bit **hash tag** packed above
it. A bucket whose tag differs cannot hold the key being looked for, so the probe rejects it from
that word alone and never touches the frame.

This matters because the bucket table is dense and walked sequentially, while the frame array is
large and touched at random: following a bucket to its frame is a likely cache miss, and on a
loaded table most of those misses were on buckets that turn out not to match. The tag confines the
common case to memory the probe is already streaming through.

The frame's full key is still compared after a tag match, so a tag collision costs one wasted
touch and never a wrong answer.

How much this is worth depends entirely on how full the table is. At a load factor around one
half it raises lookup throughput by roughly 40% at sixteen threads and 25% at one, and drops
`cache_get` from about 30% of CPU to 22%. On a sparsely loaded table it changes nothing at all:
probes end on their first bucket, and a bucket that matches was never going to be rejected. A
cache sized comfortably above its working set therefore sees none of this, and a cache sized just
under one sees most of it.

The tag's bits are cut from a slice of the hash disjoint from both the low bits that pick the
shard and the higher slice that picks the probe start, so the three decisions do not correlate.
Two index values are reserved for *empty* and *tombstone*, which is why a shard's frame count is
capped one power of two below what the index field could otherwise address.

## Eviction

Insertion may need to make room, and the sweep is a **clock**: each frame carries a
second-chance bit set on access and cleared by the sweep. The hand advances, clearing bits and
taking the first frame whose bit is already clear. Approximate LRU at a fraction of the
bookkeeping.

The sweep is bounded by a fixed number of examinations — not by a multiple of the frame count,
since that would tie how long the lock is held to how much the shard can hold. The clock exits at
the first evictable frame, so the bound is only reached when nearly everything is pinned or freshly
referenced, and the hand persists across calls: stopping short paces the work rather than abandoning
it, and the next insert resumes where this one stopped.

Eviction happens under the shard lock, so an insert that must evict holds the lock for longer
than one that does not. That is why waiters spin only briefly before yielding their core: on an
oversubscribed machine, spinning through another thread's clock sweep wastes exactly the
capacity the sweep is competing for.

:::caution[Cache sizing is not just a hit-rate knob]
The capacity also bounds the **filter** footprint. Partition range filter blobs are fetched on
demand and are meant to live here — see [SSTable](/internals/sstable). A cache too small to
hold the working set of filter partitions makes every point lookup re-read its filter, which
costs more than the filter saves.
:::

## Exactly-once reclamation

A payload must be released exactly once, and the thread that should do it is not known in
advance: it may be the evictor, or a reader that was still inside when eviction happened.

The rule is that **whoever drops the last reference reclaims**. There is no separate
reclamation pass, no epoch, no deferred list — the same reference-counting discipline the rest
of the engine uses.

Each entry carries its own reclaim function, supplied at insert. That is what lets one cache
hold both parsed btree nodes and raw byte blocks: the cache does not know what a payload is,
only how to release it.

## What it costs and what it reports

The cache is a pure optimisation — every entry can be dropped and re-read. Nothing depends on
it for correctness, which is why it can evict without coordinating with readers.

[`tidesdb_get_cache_stats`](/reference/statistics#tidesdb_get_cache_stats) reports hits,
misses, hit rate, residency, and shard count. The hit rate is cumulative since open, so it
moves slowly; compare deltas between samples rather than absolute values when tuning.

## Invariants

| Invariant | Why |
| --- | --- |
| Frames are never freed while the cache lives | A reader can pin without the frame vanishing under it |
| The frame count follows the byte budget | A frame ceiling that binds first shrinks the cache silently, while the configured budget still reports as given |
| The sweep's bound is absolute, not a multiple of the frame count | It limits how long the shard lock is held, which must not grow with how much the shard holds |
| Pin, then recheck the key | The frame may have been reused between probe and pin |
| An evicted key leaves a tombstone, not a hole | Otherwise it truncates the probe chain of later keys |
| A payload is reclaimed exactly once, by the last reference dropped | Evictor and reader race; neither may assume it is last |
| The clock sweep is bounded | An all-pinned shard must not spin forever |
| Nothing depends on the cache for correctness | It must remain free to evict at any moment |
