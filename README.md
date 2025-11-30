<div>
    <h1 align="left"><img width="128" src="artwork/tidesdb-logo-v0.1.png"></h1>
</div>

TidesDB is a fast and efficient key value storage engine library written in C. The underlying data structure is based on a log-structured merge-tree (LSM-tree).

It is not a full-featured database, but rather a library that can be used to build a database atop of or used as a standalone key-value/column store.

[![Linux Build Status](https://github.com/tidesdb/tidesdb/actions/workflows/build_and_test_tidesdb.yml/badge.svg)](https://github.com/tidesdb/tidesdb/actions/workflows/build_and_test_tidesdb.yml)

## Features
- Memtables, queue, and caches utilize a lock-free skip list with atomic CAS operations. Reads are completely lock-free and scale linearly with CPU cores. Writes use atomic CAS to prepend new versions without locks. Immutable memtable queue ensures data remains searchable during background flush operations, guaranteeing consistent reads without blocking.
- ACID transactions with full MVCC (Multi-Version Concurrency Control) supporting 5 isolation levels: `read-uncommitted`, `read-committed`, `repeatable-read` `snapshot`, and `serializable`. Each transaction operates on a consistent snapshot with sequence numbers for version ordering. Snapshot isolation provides first-committer-wins conflict detection preventing dirty reads, non-repeatable reads, and lost updates. Serializable isolation implements SSI (Serializable Snapshot Isolation) with read-write conflict detection to prevent all anomalies including write-skew. Transactions support read-your-own-writes semantics, savepoints for partial rollback, and optimistic concurrency control. Lock-free writes with atomic sequence numbers ensure ordering without blocking.
- Multi-column family atomicity guarantees that transactions spanning multiple column families either commit to all or none. Single-CF transactions use per-CF sequence numbers for maximum performance. Multi-CF transactions use global sequence numbers with high-bit flagging (bit 63) to mark entries that require atomic validation. During recovery, multi-CF transactions are only applied if all participating column families have the complete sequence, ensuring true all-or-nothing semantics without coordinator locks or two-phase commit overhead. This enables referential integrity and cross-table consistency for SQL-like workloads.
- Column families provide isolated key-value stores, each with independent configuration, memtables, SSTables, write-ahead logs, and compaction strategies. Transactions can span multiple column families with per-CF consistent snapshots. Runtime configuration updates allow dynamic tuning of write buffer size, compression, and compaction parameters without restart.
- Bidirectional iterators support seek, forward and backward traversal with heap-based merge-sort across active memtables, immutable memtables, and SSTables. Lock-free iteration with reference counting prevents premature deletion during concurrent operations. Snapshot isolation ensures consistent iteration even during concurrent writes and compactions.
- Efficient seek operations using O(log n) skip list positioning and optional succinct trie block indexes with LOUDS (Level-Order Unary Degree Sequence) encoding for direct key-to-block mapping in SSTables. Index builder samples every Nth key (default N=16) during SSTable creation to build a sparse index that maps sampled keys to block numbers. Predecessor search in the trie locates the nearest sampled key less than or equal to the target, then linear scan within the block finds the exact key. LOUDS encoding provides 2 bits per node overhead plus edge labels, with varint serialization and delta encoding for 60-80% space savings. Disk-based streaming builder maintains O(max_key_length) memory usage regardless of dataset size.
- Hybrid compaction strategy with three modes: full preemptive merge for initial levels (minimize space amplification), dividing merge at configurable dividing level (create partition boundaries), and partitioned merge for deep levels (minimize write amplification). Dynamic Capacity Adjustment (DCA) automatically scales level capacities based on largest level size using the formula C_i = N_L / T^(L-i), ensuring optimal size ratios as data grows. Dynamic level management adds and removes levels on demand. Configurable dividing level offset allows tuning the transition point between aggressive and incremental compaction strategies.
- Durability through write-ahead log (WAL) with sequence numbers for ordering and automatic recovery on startup that reconstructs memtables from persisted logs. Multi-CF transaction metadata is embedded in WAL entries, recording all participating column families for atomic recovery validation. SSTable metadata persistence ensures accurate recovery of min/max keys and entry counts. Immutable memtables remain searchable during flush, preventing data loss windows.
- Concurrent background operations with shared thread pools for flush and compaction. Multiple flush workers process different memtables in parallel without blocking reads or writes. Compaction workers coordinate via per-column-family locks to prevent conflicts while allowing parallel compaction across different column families. Background monitor thread polls column families at configurable intervals to trigger compaction when memtables exceed write buffer size or level capacities are reached.
- Optional bloom filters provide probabilistic key existence checks to reduce disk reads. Configurable false positive rate per column family. Bloom filters are built during SSTable creation and persisted in metadata blocks.
- Key-value separation (WiscKey-style) with configurable value threshold (default 1KB). Small values are stored inline with keys in the klog (key log) for fast access. Large values exceeding the threshold are stored in the vlog (value log) with only an offset stored in the klog entry. This reduces write amplification during compaction since large values are not rewritten with keys. Vlog entries are organized into fixed-size blocks (default 32KB) for efficient I/O. Both klog and vlog blocks support optional compression, though WAL entries remain uncompressed for fast writes and recovery. Configurable per column family with runtime updates.
- TTL (time-to-live) support for key-value pairs with automatic expiration. Expired entries are skipped during reads and removed during compaction. Sequence number-based MVCC ensures correct handling of expired versions.
- Custom comparators allow registration of user-defined key comparison functions with context pointers for stateful comparisons. Built-in comparators include memcmp, string, and numeric. Comparators are used consistently across skip lists, SSTables, indexes, and merge operations.
- Block manager with overflow chaining for large values. Fixed-size blocks (default 32KB) prevent fragmentation while overflow pointers chain multiple blocks for values exceeding block size. Zero-copy block caching with atomic reference counting allows multiple readers to share cached blocks without memcpy overhead. FIFO cache eviction for WAL blocks optimizes sequential access patterns. Configurable per-column-family cache sizes allow tuning for different workloads.
- Shared thread pools for background flush and compaction operations with configurable thread counts at the database level. Work queues distribute tasks across workers for parallel processing. L0 priority triggers ensure read amplification stays bounded by immediately enqueuing compaction when L0 exceeds 4 SSTables.
- Two sync modes: `TDB_SYNC_NONE` for maximum performance (OS-managed flushing) and `TDB_SYNC_FULL` for maximum durability (fsync on every write). Configurable per column family.
- Cross-platform support for Linux, macOS, and Windows on both 32-bit and 64-bit architectures with comprehensive platform abstraction layer. Atomic operations, threading primitives, and file I/O are abstracted for portability.
- Full file portability with explicit little-endian serialization throughout; database files can be copied between any platform (x86, ARM, RISC-V, PowerPC) and architecture (32-bit, 64-bit) without conversion. Fixed-width integer encoding ensures consistent layout.
- Clean C API that returns 0 on success and negative error codes on failure for straightforward error handling. Debug logging with configurable verbosity aids development and troubleshooting.

## Getting Started
To learn more about TidesDB, check out [What is TidesDB?](https://tidesdb.com/getting-started/what-is-tidesdb/).

For building and benchmarking instructions [Building & Benchmarking TidesDB](https://tidesdb.com/reference/building/)

For C usage documentation, see the [TidesDB C Reference](https://tidesdb.com/reference/c/).

## Discord Community
Join the [TidesDB Discord Community](https://discord.gg/tWEmjR66cy) to ask questions, work on development, and discuss the future of TidesDB.

## License
Multiple licenses apply to TidesDB. The primary license is the Mozilla Public License Version 2.0 (TidesDB), while additional licenses apply to the dependencies used in the project.

```
Mozilla Public License Version 2.0 (TidesDB)

-- AND --
BSD 3 Clause (Snappy)
BSD 2 (LZ4)
BSD 2 (xxHash - Yann Collet)
BSD 2 (inih - Ben Hoyt)
BSD (Zstandard)
```
