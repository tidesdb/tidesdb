<div>
    <h1 align="left"><img width="128" src="artwork/tidesdb-logo-v0.1.png"></h1>
</div>

TidesDB is a fast and efficient key value storage engine library written in C. The underlying data structure is based on a log-structured merge-tree (LSM-tree).

It is not a full-featured database, but rather a library that can be used to build a database atop of or used as a standalone key-value/column store.

[![Linux Build Status](https://github.com/tidesdb/tidesdb/actions/workflows/build_and_test_tidesdb.yml/badge.svg)](https://github.com/tidesdb/tidesdb/actions/workflows/build_and_test_tidesdb.yml)

## Features
- Memtables utilize a lock-free skip list with RCU memory management, epoch-based garbage collection, and atomic operations. Readers never block and scale linearly with CPU cores, while writers use lightweight mutex serialization per column family
- ACID transactions that are atomic, consistent, isolated, and durable across multiple column families. Point reads use READ COMMITTED isolation, iterators use snapshot isolation with reference counting.
- Column families provide isolated key-value stores, each with independent configuration, memtables, SSTables, and write-ahead logs.
- Bidirectional iterators support forward and backward traversal with heap-based merge-sort across memtables and SSTables. Lock-free iteration with reference counting prevents premature deletion during concurrent operations.
- Efficient seek operations using O(log n) skip list positioning and optional succinct trie block indexes with LOUDS encoding for direct key-to-block mapping in SSTables.
- Durability through write-ahead log (WAL) with automatic recovery on startup that reconstructs memtables from persisted logs.
- Automatic background compaction when SSTable count reaches configured threshold, or manual parallel compaction via API. Compaction removes tombstones and expired TTL entries.
- Optional bloom filters provide probabilistic key existence checks to reduce disk reads. Configurable false positive rate per column family.
- Optional compression using Snappy, LZ4, or ZSTD for both SSTables and WAL entries. Configurable per column family.
- TTL (time-to-live) support for key-value pairs with automatic expiration. Expired entries are skipped during reads and removed during compaction.
- Custom comparators allow registration of user-defined key comparison functions. Built-in comparators include memcmp, string, and numeric.
- Memory optimizations include arena-based allocation for skip list nodes and inline storage for small keys/values (≤24 bytes) to reduce malloc overhead and pointer indirection.
- Two-tier caching system with block-level LRU cache for frequently accessed data and configurable file handle cache to limit open file descriptors.
- Shared thread pools for background flush and compaction operations with configurable thread counts at the database level.
- Two sync modes: `TDB_SYNC_NONE` for maximum performance (OS-managed flushing) and `TDB_SYNC_FULL` for maximum durability (fsync on every write).
- Cross-platform support for Linux, macOS, and Windows on both 32-bit and 64-bit architectures with platform abstraction layer.
- Full file portability with explicit little-endian serialization throughout; database files can be copied between any platform (x86, ARM, RISC-V) and architecture (32-bit, 64-bit) without conversion.
- Clean C API that returns 0 on success and negative error codes on failure for straightforward error handling.

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
