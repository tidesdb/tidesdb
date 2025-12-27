<div>
    <h1 align="left"><img width="128" src="artwork/tidesdb-logo-v0.1.png"></h1>
</div>

TidesDB is a fast and efficient key value storage engine library written in C. The underlying data structure is based on a log-structured merge-tree (LSM-tree).

It is not a full-featured database, but rather a library that can be used to build a database atop of or used as a standalone key-value/column store.

[![Linux Build Status](https://github.com/tidesdb/tidesdb/actions/workflows/build_and_test_tidesdb.yml/badge.svg)](https://github.com/tidesdb/tidesdb/actions/workflows/build_and_test_tidesdb.yml)

## Features
- **Lock-free skip list memtable** with atomic CAS operations for concurrent reads and writes. Immutable memtables remain searchable during flush.
- **ACID transactions with MVCC** supporting 5 isolation levels: `READ_UNCOMMITTED`, `READ_COMMITTED`, `REPEATABLE_READ`, `SNAPSHOT`, and `SERIALIZABLE`. Serializable isolation uses SSI (Serializable Snapshot Isolation) with read-write conflict detection to prevent all anomalies including write-skew. Transactions support savepoints for partial rollback and read-your-own-writes semantics.
- **Multi-column family transactions** with atomic all-or-nothing semantics. Global sequence numbers ensure total ordering. Multi-CF transaction metadata is embedded in WAL entries for atomic recovery validation.
- **Column families** provide isolated key-value stores with independent configuration (memtable size, compression, bloom filters, compaction parameters). Runtime configuration updates without restart.
- **Bidirectional iterators** with heap-based merge-sort across memtables and SSTables. Snapshot isolation ensures consistent iteration during concurrent writes and compactions.
- **Hybrid compaction** with three modes: full preemptive merge (minimize space amplification), dividing merge (create partition boundaries), and partitioned merge (minimize write amplification). Dynamic Capacity Adjustment (DCA) automatically scales level capacities based on data size. Dynamic level management adds/removes levels on demand.
- **Write-ahead log (WAL)** with automatic recovery on startup. Lock-free group commit batches concurrent writes using atomic reservation and CAS-based leader election.
- **Optional bloom filters** (configurable false positive rate) reduce disk reads for absent keys. Built during SSTable creation and persisted in metadata.
- **Key-value separation** (WiscKey-style) with configurable threshold (default 4KB). Small values stored inline in klog, large values in vlog with offset reference. Reduces write amplification during compaction.
- **TTL support** for automatic key-value expiration. Expired entries skipped during reads and removed during compaction.
- **Custom comparators** with lock-free atomic COW registry. Built-in comparators: memcmp, lexicographic, reverse. Used consistently across skip lists, SSTables, and compaction.
- **Lock-free block manager** using `pread`/`pwrite` for concurrent I/O. Reference-counted blocks with atomic operations. xxHash32 checksums for integrity. Supports up to 4GB blocks with partial reads.
- **Two-tier caching**
  - File handle cache with LRU eviction (default 512 open SSTables). Background reaper closes oldest unused files.
  - Block cache using partitioned CLOCK eviction (2 partitions per CPU core, default 64MB). Caches deserialized klog blocks with zero-copy API and reference bit protection.
- **Background thread pools** for flush and compaction (default 2 threads each). Work queues distribute tasks. Compaction auto-triggers when Level 1 reaches 4 files (Spooky α parameter).
- **Three sync modes** · `TDB_SYNC_NONE` (OS-managed), `TDB_SYNC_FULL` (fsync every write), `TDB_SYNC_INTERVAL` (periodic sync). Structural operations always enforce durability.
- **Compression support** · LZ4, Zstd, Snappy (configurable per column family). Applied to klog and vlog blocks, not WAL.
- **Block indexes** for fast seeks. Sample every Nth block (configurable ratio, default 1 = every block) storing prefix boundaries and file positions for binary search.
- **Cross-platform** · Linux, macOS, Windows, BSD variants, Solaris/Illumos on x86, ARM, RISC-V, PowerPC (32-bit and 64-bit). Comprehensive platform abstraction layer (`compat.h`).
- **File portability** · Little-endian serialization throughout. Database files work across any platform/architecture without conversion.
- **Clean C API** · Returns 0 on success, negative error codes on failure. Configurable debug logging.

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