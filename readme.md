# TidesDB
TidesDB is a library that provides an embeddable, persistent key-value store for fast flash and ram storage.

TidesDB has a robust feature-set, and was designed to be a high-performance, low-latency storage engine. It is optimized for read-heavy workloads, and is ideal for applications that require fast data retrieval.

TidesDB is built on the principles of the Log-Structured Merge-Tree (LSM-Tree) data structure.
TidesDB utilizes an in-memory AVL tree, known as a memtable, for temporarily storing key-value pairs. These pairs are then flushed to Sorted String Tables (SSTables) on disk. When the number of SSTables reaches a specified threshold, the compaction process is triggered.
This process merges multiple SSTables into fewer ones, reducing file count and minimizing disk I/O for read operations. Additionally, the system maintains a minimum number of SSTables to further optimize read perfor

## Features
- [x] Key-Value storage engine
- [x] Variable-length byte array keys and values
- [x] Simple API (`Put`, `Get`, `Delete`)
- [x] Paged SSTable with overflow management
- [x] LSM-Tree data structure implementation
- [x] Write-ahead logging
- [x] Recovery/Replay WAL (`RunRecoveredOperations`)
- [x] AVL tree memtable
- [x] Transaction control (`BeginTransaction`, `CommitTransaction`, `RollbackTransaction`)
- [x] Concurrent safe
- [] Compression (todo)
- [x] Tombstone deletion
- [] Range functionality (NGet, Range, NRange, GreaterThan, LessThan, GreaterThanEq, LessThanEq)

## Requirements
## Protobuf
```bash
sudo apt-get install libprotobuf-dev protobuf-compiler
```
