<div>
    <h1 align="center"><img width="328" src="artwork/tidesdb-logo.png"></h1>
</div>

TidesDB is a library that provides an embeddable, persistent key-value store for fast flash and ram storage.

TidesDB has a robust feature-set, and was designed to be a high-performance, low-latency storage engine. It is optimized for write and read-heavy workloads.

TidesDB is built on the principles of the Log-Structured Merge-Tree (LSM-Tree) data structure.
TidesDB utilizes an in-memory lockless skip list, known as a memtable, for temporarily storing key-value pairs. These pairs are then flushed to Sorted String Tables (SSTables) on disk. When the number of SSTables reaches a specified threshold, the compaction process is triggered.

This process merges pairs of SSTables into a new SSTable, and deletes any redundant data. The compaction process ensures that the number of SSTables remains low, and that read performance is optimized.

> [!WARNING]
> Still in beta stages, use at your own risk and check back often for updates.

## Features
- [x] Embeddable storage engine
- [x] Variable-length byte array keys and values
- [x] Simple API (`Put`, `Get`, `Delete`)
- [x] Range functionality (`NGet`, `Range`, `NRange`, `GreaterThan`, `LessThan`, `GreaterThanEq`, `LessThanEq`)
- [x] Custom pager for SSTables and WAL
- [x] LSM-Tree data structure implementation (log structured merge tree)
- [x] Write-ahead logging
- [x] Recovery/Replay WAL (`RunRecoveredOperations`)
- [x] In-memory lockless skip list (memtable)
- [x] Transaction control (`BeginTransaction`, `CommitTransaction`, `RollbackTransaction`)
- [x] Concurrent safe
- [x] Tombstone deletion
- [x] Minimal blocking on flushing, and compaction operations
- [x] Background memtable flushing
- [x] Background paired multithreaded compaction
- [x] Configurable options
- [ ] Compression (todo)
## Design
Single level meaning 1 memtable and multiple sstables.  No hierarchical levels.

## Requirements
Whats required to build TidesDB..

### Protobuf
```bash
sudo apt-get install libprotobuf-dev protobuf-compiler
```

### Gtest
.. maybe coming soon