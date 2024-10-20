<div>
    <h1 align="center"><img width="328" src="artwork/tidesdb-logo.png"></h1>
</div>

TidesDB is a library that provides an embeddable, persistent key-value store for fast flash and ram storage.

TidesDB has a robust feature-set, and was designed to be a high-performance, low-latency storage engine. It is optimized for write and read-heavy workloads.

TidesDB is built on the principles of the Log-Structured Merge-Tree (LSM-Tree) data structure.
TidesDB utilizes an in-memory AVL tree, known as a memtable, for temporarily storing key-value pairs. These pairs are then flushed to Sorted String Tables (SSTables) on disk. When the number of SSTables reaches a specified threshold, the compaction process is triggered.

This process merges pairs of SSTables into a new SSTable, and deletes any redundant, tombstoned data. The compaction process ensures that the number of SSTables remains low, and that read performance is optimized.

> [!WARNING]
> Still in beta stages, use at your own risk and check back often for updates.

## Features
- [x] Lightweight embeddable storage engine
- [x] Variable-length byte array keys and values
- [x] Simple yet effective API (`Put`, `Get`, `Delete`, `PutBatch`, `DeleteBatch`)
- [x] Range functionality (`NGet`, `Range`, `NRange`, `GreaterThan`, `LessThan`, `GreaterThanEq`, `LessThanEq`)
- [x] Custom pager for SSTables and WAL
- [x] LSM-Tree data structure implementation (log structured merge tree)
- [x] Write-ahead logging (WAL queue for faster writes)
- [x] Crash Recovery/Replay WAL (`Recover`)
- [x] In-memory AVL tree (memtable)
- [x] Transaction control (`BeginTransaction`, `CommitTransaction`, `RollbackTransaction`) on failed commit the transaction is automatically rolled back
- [x] Tombstone deletion
- [x] Minimal blocking on flushing, and compaction operations
- [x] Background memtable flushing
- [x] Background paired multithreaded compaction
- [x] Configurable memtable and compaction options
- [x] Support for large amounts of data
- [x] Threadsafe
- [x] Granular page locking mechanisms on reads
- [x] ZSTD Compression sstables if enabled
- [x] Debug logging (optional, degrades performance)

## Design
Single level meaning 1 memtable and multiple sstables.  No hierarchical levels.

## Requirements
Whats required to build TidesDB?

### Protobuf
#### Installing Protocol Buffers

##### Unix/Linux
```bash
sudo apt-get update
sudo apt-get install -y protobuf-compiler libprotobuf-dev
protoc --version
```

##### MacOS
```bash
brew install protobuf
protoc --version
```

##### Windows
```bash
vcpkg install protobuf
```

### ZSTD
#### Installing ZSTD

##### Unix/Linux
```bash
sudo apt-get install -y libzstd-dev
```

#### Windows
```bash
vcpkg install zstd
```

## Bindings
- C

## FFI (Foreign Function Interfaces)
- Go
- Python
- Rust
- NodeJS
- Java
- Haskell
- Lua
- Ruby

The FFIs are still in their early stages.

## Interested in joining the project?
Hey you, yeah you!  Are you interested in joining the TidesDB project?
We are always looking for talented individuals to join our open-source project.

Email us at [hello@tidesdb.com](mailto:hello@tidesdb.com) with some information about yourself and how you can contribute to the project.