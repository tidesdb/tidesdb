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
- [x] Lightweight embeddable storage engine
- [x] Variable-length byte array keys and values
- [x] Simple yet effective API (`Put`, `Get`, `Delete`)
- [x] Range functionality (`NGet`, `Range`, `NRange`, `GreaterThan`, `LessThan`, `GreaterThanEq`, `LessThanEq`)
- [x] Custom pager for SSTables and WAL
- [x] LSM-Tree data structure implementation (log structured merge tree)
- [x] Write-ahead logging (WAL queue for faster writes)
- [x] Crash Recovery/Replay WAL (`Recover`)
- [x] In-memory lockfree skip list (memtable)
- [x] Transaction control (`BeginTransaction`, `CommitTransaction`, `RollbackTransaction`) on failed commit the transaction is automatically rolled back
- [x] Tombstone deletion
- [x] Minimal blocking on flushing, and compaction operations
- [x] Background memtable flushing
- [x] Background paired multithreaded compaction
- [x] Configurable options
- [x] Support for large amounts of data
- [x] Threadsafe
- [ ] Compression (todo, LZ4, Snappy)

## Design
Single level meaning 1 memtable and multiple sstables.  No hierarchical levels.

## Requirements
Whats required to build TidesDB.

### Protobuf
```bash
sudo apt-get install libprotobuf-dev protobuf-compiler
```

### Bindings
- C (coming soon)

### FFI (Foreign Function Interfaces)
- Go (coming soon)
- Python (coming soon)
- Rust (coming soon)
- NodeJS (coming soon)
- Java (coming soon)
- Haskell (coming soon)
- Lua (coming soon)
- Ruby (coming soon)

### Interested in joining the project?
Email us at [hello@tidesdb.com](mailto:hello@tidesdb.com)