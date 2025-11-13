<div>
    <h1 align="left"><img width="128" src="artwork/tidesdb-logo-v0.1.png"></h1>
</div>

TidesDB is a fast and efficient key value storage engine library written in C. The underlying data structure is based on a log-structured merge-tree (LSM-tree).

It is not a full-featured database, but rather a library that can be used to build a database atop of or used as a standalone key-value/column store.

[![Linux Build Status](https://github.com/tidesdb/tidesdb/actions/workflows/build_and_test_tidesdb.yml/badge.svg)](https://github.com/tidesdb/tidesdb/actions/workflows/build_and_test_tidesdb.yml)

## Features
- **Lock-free concurrency**: Skip list memtables with RCU memory management, epoch-based garbage collection, and atomic operations. Readers never block (scale linearly with cores), writers use lightweight mutex serialization per column family.
- **ACID transactions**: Atomic, consistent, isolated, and durable across multiple column families. READ COMMITTED isolation for point reads, snapshot isolation for iterators.
- **Column families**: Isolated key-value stores with independent configuration, memtables, SSTables, and WALs.
- **Bidirectional iterators**: Forward/backward iteration with heap-based merge-sort. Lock-free with reference counting prevents premature deletion.
- **Efficient seeks**: O(log n) skip list positioning and optional succinct trie block indexes (LOUDS encoding) for direct key-to-block-number mapping in SSTables.
- **Durability**: Write-ahead log (WAL) with automatic recovery on startup.
- **Compaction**: Automatic background compaction (configurable threshold) or manual parallel compaction via API. Removes tombstones and expired TTL entries.
- **Bloom filters**: Optional probabilistic filters reduce disk reads. Configurable false positive rate.
- **Compression**: Optional Snappy, LZ4, or ZSTD for SSTables and WAL entries.
- **TTL support**: Time-to-live for key-value pairs. Expired entries automatically skipped.
- **Custom comparators**: Register custom key comparison functions (built-in: memcmp, string, numeric).
- **Memory optimizations**: Arena-based allocation for skip list nodes, inline storage for small keys/values (≤24 bytes).
- **Caching**: Block-level LRU cache and configurable file handle cache (`max_open_file_handles`).
- **Thread pools**: Shared flush and compaction thread pools with configurable counts.
- **Sync modes**: TDB_SYNC_NONE (fastest) or TDB_SYNC_FULL (most durable).
- **Cross-platform**: Linux, macOS, Windows (32-bit and 64-bit) with platform abstraction layer.
- **Simple C API**: Returns 0 on success, negative error codes on failure.

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
