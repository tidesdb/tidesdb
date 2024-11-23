TidesDB is a fast and efficient key value storage engine library written in C.
The underlying data structure is based on a log-structured merge-tree (LSM-tree).

TidesDB is designed to be fast, simple, durable and efficient.  It is not a full-featured database, but rather a library that can be used to build a database atop of.

> [!WARNING]
> In very active beta development. Not ready for production use.

## Features
- [] **Concurrent** multiple threads can read and write to the storage engine.  The skiplist is granularly locked.  SSTables are sorted, immutable and can be read concurrently and are protected via page locks.
- [] **Column Families** store data in separate key-value stores.
- [] **Atomic Transactions** commit or rollback multiple operations atomically.
- [] **Cursor** iterate over key-value pairs forward and backward.
- [] **WAL** write-ahead logging for durability.
- [] **Multithreaded Compaction** manual paired and merged compaction data to reduce disk usage.
- [] **Background flush** memtable flushes are enqueued and then flushed in the background.
- [x] **Chained Bloom Filters** reduce disk reads by reading initial pages of sstables to check key existence.  Bloomfilters grow with the size of the sstable using chaining and linking.
- [x] **Zstandard Compression** compression is achieved with Zstandard.  SStable entries can be compressed as well as WAL entries.
- [x] **TTL** time-to-live for key-value pairs.

## License
Multiple
```
Mozilla Public License Version 2.0
BSD 2-Clause license
```