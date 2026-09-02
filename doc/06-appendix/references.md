---
title: References
description: The published work TidesDB's design draws on.
slug: appendix/references
part: appendix
sidebar:
  order: 5
---

# References

Work TidesDB builds on directly. [Design lineage](/internals/design-lineage) sets out what is
implemented as published and where the engine departs.

## Compaction

**[Spooky]** Niv Dayan, Tamar Weiss, Shmuel Dashesky, Michael Pan, Edward Bortnikov, and Moshe
Twitto. *Spooky: Granulating LSM-Tree Compactions Correctly.* Proceedings of the VLDB Endowment,
15(11), 2022, pp. 3071–3084.
<https://vldb.org/pvldb/vol15/p3071-dayan.pdf>

Establishes that Full Merge and Partial Merge each fail differently — the first on space
amplification, the second on write amplification and SSD garbage collection — and resolves both by
partitioning the largest level into equal files and partitioning smaller levels on those
boundaries, so one group of perfectly overlapping files merges at a time. TidesDB takes its
dividing level and its capacity model from this paper.

**[DCA]** Siying Dong, Mark Callaghan, Leonidas Galanis, Dhruba Borthakur, Tony Savor, and
Michael Strum. *Optimizing Space Amplification in RocksDB.* CIDR, 2017.

Dynamic Capacity Adaptation. Sizes the capacities of levels `1..L-1` from the largest level's
actual data size rather than its capacity, bounding durable space amplification to `1/(T-1)`.
Predates Spooky, which cites and leverages it — TidesDB implements it in
`compaction_planner_capacities`.

## Key/value separation

**[WiscKey]** Lanyue Lu, Thanumalayan Sankaranarayana Pillai, Andrea C. Arpaci-Dusseau, and
Remzi H. Arpaci-Dusseau. *WiscKey: Separating Keys from Values in SSD-Conscious Storage.* USENIX
FAST '16.
<https://www.usenix.org/conference/fast16/technical-sessions/presentation/lu>

Observes that LSM compaction rewrites values repeatedly although only keys need sorting, and
separates them so compaction moves keys alone. Also sets out the costs separation introduces —
range queries become random reads, the value log needs its own garbage collection, and crash
consistency spans two structures. TidesDB takes the separation and diverges on all three
mitigations.

## Logging

**[Aether]** Ryan Johnson, Ippokratis Pandis, Radu Stoica, Manos Athanassoulis, and Anastasia
Ailamaki. *Aether: A Scalable Approach to Logging.* Proceedings of the VLDB Endowment, 3(1), 2010.

Identifies log-space allocation contention and the serialization of many small writes as the
scalability limits of write-ahead logging, and answers them with a consolidation array and flush
pipelining. TidesDB's buffered append ring has that shape: the ring's single reserving atomic is the
consolidation, and its flush thread is the pipelining.

## Supporting

**[xxHash]** Yann Collet. *xxHash — Extremely fast non-cryptographic hash algorithm.*
<https://github.com/Cyan4973/xxHash>

XXH3 provides the block checksum every framed record carries, and the key hashes the block
cache, the manifest index, the partition filter and the write-reservation table index with.
