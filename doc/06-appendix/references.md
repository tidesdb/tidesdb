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

## Transactions and isolation

The definitions the isolation levels are held to, and the protocol the commit path follows. [Design
lineage](/internals/design-lineage) sets out what each contributed and where TidesDB departs.

**[Berenson]** Hal Berenson, Phil Bernstein, Jim Gray, Jim Melton, Elizabeth O'Neil, and Patrick
O'Neil. *A Critique of ANSI SQL Isolation Levels.* SIGMOD, 1995 (MSR-TR-95-51).
<https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/tr-95-51.pdf>

Defines snapshot isolation and first-committer-wins: a transaction commits only if no other
transaction with a commit timestamp inside its execution interval wrote data it also wrote, which is
what prevents lost updates. Names the write-skew anomaly (A5B) snapshot isolation admits. TidesDB's
snapshot level is this definition.

**[Adya]** Atul Adya, Barbara Liskov, and Patrick O'Neil. *Generalized Isolation Level
Definitions.* ICDE, 2000; and Atul Adya, *Weak Consistency: A Generalized Theory and Optimistic
Implementations for Distributed Transactions*, MIT, 1999 (TR-786).
<https://pmg.csail.mit.edu/papers/adya-phd.pdf>

The phenomena G0, G1, G2 and G2-item over a serialization graph, and the levels PL-1 to PL-3 that
forbid them. TidesDB's levels are specified against these rather than the ANSI wording: repeatable
read forbids G2-item, snapshot forbids G1 and G-SI, serializable forbids G2 over predicates too.

**[Fekete]** Alan Fekete, Dimitrios Liarokapis, Elizabeth O'Neil, Patrick O'Neil, and Dennis
Shasha. *Making Snapshot Isolation Serializable.* ACM Transactions on Database Systems, 30(2), 2005.
<https://www.cse.iitb.ac.in/infolab/Data/Courses/CS632/2009/Papers/p492-fekete.pdf>

Shows that a committer need only check concurrent transactions that have already committed; those
still active check for its writes when they commit. That observation is why TidesDB's validation is
one store probe for the committed and one look at the claims in flight for the rest, and why
refusing the second claimant while the first is in flight admits the same histories as
first-committer-wins.

**[Cahill]** Michael J. Cahill, Uwe Röhm, and Alan D. Fekete. *Serializable Isolation for Snapshot
Databases.* SIGMOD, 2008; ACM Transactions on Database Systems, 34(4), 2009.
<https://people.eecs.berkeley.edu/~kubitron/courses/cs262a-F13/handouts/papers/p729-cahill.pdf>

Serializable snapshot isolation: the dangerous structure of two consecutive read-write edges, and
SIREAD locks kept until every concurrent transaction has completed. TidesDB took the rule that a
prepared transaction keeps its read footprint held, and did not take the pivot rule itself.

**[Ports]** Dan R. K. Ports and Kevin Grittner. *Serializable Snapshot Isolation in PostgreSQL.*
Proceedings of the VLDB Endowment, 5(12), 2012.
<https://drkp.net/papers/ssi-vldb12.pdf>

The production account of SSI: predicate locks at tuple, page and relation granularity, SIREAD locks
retained until all concurrent transactions commit, and a prepared transaction that keeps its locks
and is never chosen as the victim. The last is the reason a TidesDB prepare claims what it read.

**[Yabandeh]** Daniel Gómez Ferro and Maysam Yabandeh. *A Critique of Snapshot Isolation.* EuroSys,
2012. <https://arxiv.org/pdf/2405.18393>

Write-snapshot isolation: a transaction does not commit if its read set was modified by a concurrent
transaction, and that alone is serializable. TidesDB's read validation at repeatable read and
serializable is this rule, over keys and over the intervals its scans covered.

**[Kung]** H. T. Kung and John T. Robinson. *On Optimistic Methods for Concurrency Control.* ACM
Transactions on Database Systems, 6(2), 1981.

The original optimistic protocol: read phase, validation, write phase, with parallel validation
against transactions past their read phase but not past their write phase. TidesDB's order of
claiming before drawing the sequence and validating after it is this protocol's.

**[Silo]** Stephen Tu, Wenting Zheng, Eddie Kohler, Barbara Liskov, and Samuel Madden. *Speedy
Transactions in Multicore In-Memory Databases.* SOSP, 2013.
<https://people.csail.mit.edu/stephentu/papers/silo.pdf>

Locks the write set in a global order, fences, validates the read set and the scanned node set, and
chooses the transaction id after validation. TidesDB's claims are sorted into one order for the same
reason, its fence between the last claim and the draw is Silo's, and its scan footprint stands where
Silo's node set does.

**[Hekaton]** Per-Åke Larson, Spyros Blanas, Cristian Diaconu, Craig Freedman, Jignesh M. Patel,
and Mike Zwilling. *High-Performance Concurrency Control Mechanisms for Main-Memory Databases.*
Proceedings of the VLDB Endowment, 5(4), 2011.
<https://www.vldb.org/pvldb/vol5/p298_per-akelarson_vldb2012.pdf>

Backward validation of read stability as of the end of the transaction, and phantoms caught by
re-running each scan. TidesDB validates a read at its own commit sequence for the same reason, and
asks the store about a scanned interval rather than re-running the scan.

**[Percolator]** Daniel Peng and Frank Dabek. *Large-scale Incremental Processing Using Distributed
Transactions and Notifications.* OSDI, 2010.
<https://www.usenix.org/legacy/event/osdi10/tech/full_papers/Peng.pdf>

An exact per-key record of the last commit, never aged out, consulted at prewrite. The comparison
point for what a bounded conflict table gives up.

**[Omid]** Ohad Shacham, Francisco Perez-Sorrosal, Edward Bortnikov, Eshcar Hillel, Idit Keidar,
Ivan Kelly, Matthieu Morel, and Sameer Paranjpye. *Omid, Reloaded: Scalable and Highly-Available
Transaction Processing.* FAST, 2017.
<https://www.usenix.org/system/files/conference/fast17/fast17-shacham.pdf>

A conflict map of buckets holding key hashes and commit timestamps, in which a transaction that finds
no old-enough entry and no empty slot aborts. The design TidesDB's hashed reservation table
resembled, and whose false aborts under a wide commit are the reason it was replaced.

**[Centiman]** Bailu Ding, Lucja Kot, Alan Demers, and Johannes Gehrke. *Centiman: Elastic, High
Performance Optimistic Concurrency Control by Watermarking.* SoCC, 2015.
<https://www.cs.cornell.edu/~blding/pub/centiman_socc_2015.pdf>

Validators over truncated write sets, with the abort a conservative validator has no choice but to
take when the history it needs is gone. Names the cost TidesDB avoids by keeping claims exact and
owned by the committer.

**[Deuteronomy]** Justin Levandoski, David Lomet, Sudipta Sengupta, Ryan Stutsman, and Rui Wang.
*High Performance Transactions in Deuteronomy.* CIDR, 2015.
<https://www.cidrdb.org/cidr2015/Papers/CIDR15_Paper15.pdf>

A hash table of recent versions whose entries carry a fixed-size hash of the key and a pointer to the
full key, compared in full on a match. The precedent for comparing a claim by its bytes rather than
trusting its hash.

**[Wu]** Yingjun Wu, Joy Arulraj, Jiexi Lin, Ran Xian, and Andrew Pavlo. *An Empirical Evaluation
of In-Memory Multi-Version Concurrency Control.* Proceedings of the VLDB Endowment, 10(7), 2017.
<https://www.vldb.org/pvldb/vol10/p781-Wu.pdf>

The survey of multi-version protocols, version storage and garbage collection the design was read
against; its account of optimistic validation's abort cost under contention is the background to the
retry rate the statistics now report.

## Supporting

**[xxHash]** Yann Collet. *xxHash — Extremely fast non-cryptographic hash algorithm.*
<https://github.com/Cyan4973/xxHash>

XXH3 provides the block checksum every framed record carries, and the key hashes the block
cache, the manifest index, the partition filter and the in-flight claim set index with.
