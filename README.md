<div>
    <h1 align="left"><img width="128" src="artwork/tidesdb-logo-v0.1.png"></h1>
</div>

TidesDB is a fast and efficient key value storage engine library written in C. The underlying data structure is based on a log-structured merge-tree (LSM-tree).

It is not a full-featured database, but rather a library that can be used to build a database atop of or used as a standalone key-value/column store.

[![Linux Build Status](https://github.com/tidesdb/tidesdb/actions/workflows/build_and_test_tidesdb.yml/badge.svg)](https://github.com/tidesdb/tidesdb/actions/workflows/build_and_test_tidesdb.yml)

## Features
- Memtables utilize a lock-free skip list with atomic CAS operations. Reads are completely lock-free and scale linearly with CPU cores. Writes use atomic CAS to prepend new versions without locks. Immutable memtable queue ensures data remains searchable during background flush operations, guaranteeing consistent reads without blocking.
- ACID transactions with full MVCC (Multi-Version Concurrency Control) supporting four isolation levels: read-uncommitted, read-committed, repeatable-read, and serializable. Each transaction operates on a consistent snapshot with sequence numbers for version ordering. Transactions support read-your-own-writes semantics, savepoints for partial rollback, and optimistic concurrency control with conflict detection. Multi-column family transactions allow atomic writes across multiple column families with proper isolation. Lock-free writes with atomic sequence numbers ensure ordering without blocking.
- Column families provide isolated key-value stores, each with independent configuration, memtables, SSTables, write-ahead logs, and compaction strategies. Transactions can span multiple column families with consistent snapshots. Runtime configuration updates allow dynamic tuning of write buffer size, compression, and compaction parameters without restart.
- Bidirectional iterators support forward and backward traversal with heap-based merge-sort across active memtables, immutable memtables, and SSTables. Lock-free iteration with reference counting prevents premature deletion during concurrent operations. Snapshot isolation ensures consistent iteration even during concurrent writes and compactions.
- Efficient seek operations using O(log n) skip list positioning and optional succinct trie block indexes with LOUDS encoding for direct key-to-block mapping in SSTables. Range queries benefit from sorted key ordering and skip list structure.
- Advanced compaction policies with three merge algorithms: full preemptive merge for initial levels, dividing merge with configurable offset for mid-levels, and partitioned merge for deep levels. Dynamic Capacity Adjustment (DCA) automatically adds and removes levels based on data volume. Configurable level size ratios and dividing level offsets allow fine-tuning for different workloads.
- Durability through write-ahead log (WAL) with sequence numbers for ordering and automatic recovery on startup that reconstructs memtables from persisted logs. SSTable metadata persistence ensures accurate recovery of min/max keys and entry counts. Immutable memtables remain searchable during flush, preventing data loss windows.
- Concurrent background operations with shared thread pools for flush and compaction. Multiple flush workers process different memtables in parallel without blocking reads or writes. Compaction workers coordinate via per-column-family locks to prevent conflicts while allowing parallel compaction across column families.
- Optional bloom filters provide probabilistic key existence checks to reduce disk reads. Configurable false positive rate per column family. Bloom filters are built during SSTable creation and persisted in metadata blocks.
- Optional compression using Snappy, LZ4, or ZSTD for SSTable data blocks. WAL entries remain uncompressed for fast writes and recovery. Configurable per column family with runtime updates.
- TTL (time-to-live) support for key-value pairs with automatic expiration. Expired entries are skipped during reads and removed during compaction. Sequence number-based MVCC ensures correct handling of expired versions.
- Custom comparators allow registration of user-defined key comparison functions with context pointers for stateful comparisons. Built-in comparators include memcmp, string, and numeric. Comparators are used consistently across skip lists, SSTables, and merge operations.
- Block manager cache with FIFO operations and configurable file handle cache to limit open file descriptors. Per-column-family cache sizes allow tuning for different access patterns.
- Shared thread pools for background flush and compaction operations with configurable thread counts at the database level. Work queues distribute tasks across workers for parallel processing.
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
