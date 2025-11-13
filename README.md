<div>
    <h1 align="left"><img width="128" src="artwork/tidesdb-logo-v0.1.png"></h1>
</div>

TidesDB is a fast and efficient key value storage engine library written in C. The underlying data structure is based on a log-structured merge-tree (LSM-tree).

It is not a full-featured database, but rather a library that can be used to build a database atop of or used as a standalone key-value/column store.

[![Linux Build Status](https://github.com/tidesdb/tidesdb/actions/workflows/build_and_test_tidesdb.yml/badge.svg)](https://github.com/tidesdb/tidesdb/actions/workflows/build_and_test_tidesdb.yml)

## Features
- Lock-free skip list memtables with atomic operations and RCU (Read-Copy-Update) memory management for exceptional read performance
- True lock-free reads - readers never acquire locks, never block, and scale linearly with CPU cores
- Single-writer serialization per column family using lightweight mutex, ensuring write atomicity without complex locking
- RCU-based memory reclamation with epoch-based garbage collection prevents use-after-free while maintaining lock-free reads
- Atomic pointer operations with acquire/release memory ordering for correct synchronization without locks
- Writers don't block readers. Readers never block other readers or writers. Background operations don't affect active transactions.
- ACID transactions that are atomic, consistent, isolated, and durable. Transactions support multiple operations across column families.
- Point reads use READ COMMITTED isolation (see latest committed data), while iterators use snapshot isolation (consistent point-in-time view via reference counting).
- Mark-and-insert update strategy for lock-free consistency - updates mark old nodes as deleted and insert new nodes atomically.
- Isolated key-value stores. Each column family has its own configuration, memtables, sstables, and write ahead logs.
- Bidirectional iterators that allow you to iterate forward and backward over key-value pairs with heap-based merge-sort across memtable and sstables.
- Lock-free iteration with reference counting prevents premature deletion during iteration without blocking writers.
- Effective seek operations with O(log n) skip list positioning and succinct trie block index positioning (if enabled) in sstables.
- Durability through WAL (write ahead log). Automatic recovery on startup reconstructs memtables from WALs.
- Optional automatic background compaction when sstable count reaches configured max per column family. You can also trigger manual compactions through the API, parallelized or not.
- Optional bloom filters to reduce disk reads by checking key existence before reading sstables. Configurable false positive rate.
- Optional compression via Snappy, LZ4, or ZSTD for sstables and WAL entries. Configurable per column family.
- Optional TTL (time-to-live) for key-value pairs. Expired entries automatically skipped during reads.
- Optional custom comparators. You can register custom key comparison functions. Built-in comparators include memcmp, string, numeric.
- You can enable column families to utilize block caching (most recent blocks).
- Two sync modes NONE (fastest), FULL (most durable, slowest).
- Per-column-family configuration includes memtable size, compaction settings, compression, bloom filters, sync mode, and more.
- Clean, easy-to-use C API. Returns 0 on success, -n on error.
- Cross-platform support for 32bit and 64bit Linux, macOS, and Windows with platform abstraction layer.
- Optional succinct trie block indexes for fast sstable lookups. Provides direct key-to-block offset mapping without full sstable scans. Uses LOUDS (Level-Order Unary Degree Sequence) representation for memory-efficient compressed storage with O(1) navigation operations. Significantly reduces memory footprint compared to traditional hash-based indexes while maintaining fast lookup performance.
- Efficient deletion through tombstone markers. Removed during compactions.
- Configurable LRU cache for open file handles. Limits system resources while maintaining performance. Set `max_open_file_handles` to control cache size (0 = disabled).
- Storage engine thread pools for background flush and compaction with configurable thread counts.
- Arena-based memory allocation for skip list nodes reduces malloc overhead and improves cache locality.
- Inline storage optimization for small keys/values (≤24 bytes) eliminates pointer indirection and improves performance.

## Getting Started
To learn more about TidesDB, check out [What is TidesDB?](https://tidesdb.com/getting-started/what-is-tidesdb/).

For building and benchmarking instructions [Building & Benchmarking TidesDB](https://tidesdb.com/reference/building/)

For C usage documentation, see the [TidesDB C Reference](https://tidesdb.com/reference/c/).

## Discord Community
Join the [TidesDB Discord Community](https://discord.gg/tWEmjR66cy) to ask questions, work on development, and discuss the future of TidesDB.

## License
Multiple

```
Mozilla Public License Version 2.0 (TidesDB)

-- AND --
BSD 3 Clause (Snappy)
BSD 2 (LZ4)
BSD 2 (xxHash - Yann Collet)
BSD 2 (inih - Ben Hoyt)
BSD (Zstandard)
Apache 2.0 (OpenSSL 3.0+) / OpenSSL License (OpenSSL 1.x)
```
