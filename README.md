<div>
    <h1 align="left"><img width="148" src="artwork/tidesdb-logo-v0.1.png"></h1>
</div>

TidesDB is a fast and efficient key value storage engine library written in C.
The underlying data structure is based on a log-structured merge-tree (LSM-tree).

It is not a full-featured database, but rather a library that can be used to build a database atop of.

> [!CAUTION]
> In very active beta development. Not ready for production use.  The library is not yet stable.

## Features
- [x] **Concurrent** multiple threads can read and write to the storage engine.  The skiplist uses an RW lock which means multiple readers and one true writer.  SSTables are sorted, immutable and can be read concurrently they are protected via page locks.
- [x] **Column Families** store data in separate key-value stores.
- [x] **Atomic Transactions** commit or rollback multiple operations atomically.
- [x] **Cursor** iterate over key-value pairs forward and backward.
- [x] **WAL** write-ahead logging for durability.  As operations are appended they are also truncated at specific points once persisted to an sstable(s).
- [x] **Multithreaded Compaction** manual multi-threaded paired and merged compaction of sstables.  When run for example 10 sstables compacts into 5 as their paired and merged.  Each thread is responsible for one pair - you can set the number of threads to use for compaction.
- [x] **Background flush** memtable flushes are enqueued and then flushed in the background.
- [x] **Chained Bloom Filters** reduce disk reads by reading initial pages of sstables to check key existence.  Bloomfilters grow with the size of the sstable using chaining and linking.
- [x] **Zstandard Compression** compression is achieved with Zstandard.  SStable entries can be compressed as well as WAL entries.
- [x] **TTL** time-to-live for key-value pairs.
- [x] **Configurable** many options are configurable for the engine, and column families.
- [x] **Error Handling** majority of functions return an error code.
- [x] **Easy API** simple and easy to use api.

## Errors
> [!CAUTION]
> Errors are not finalized and may change.

```
| Error Code | Error Message                                                        |
|------------|----------------------------------------------------------------------|
| 1000       | Failed to allocate memory for new db                                 |
| 1001       | Config is NULL                                                       |
| 1002       | TidesDB is NULL                                                      |
| 1003       | DB path is NULL                                                      |
| 1004       | Failed to create db directory                                        |
| 1005       | Failed to unlock flush lock                                          |
| 1006       | Failed to join flush thread                                          |
| 1007       | Failed to destroy flush lock                                         |
| 1008       | Failed to sort sstables                                              |
| 1009       | Failed to replay wal                                                 |
| 1010       | Failed to initialize flush queue                                     |
| 1011       | Failed to copy memtable                                              |
| 1012       | Failed to get wal checkpoint                                         |
| 1013       | Failed to initialize column families lock                            |
| 1014       | Failed to start flush thread                                         |
| 1015       | Column family name is NULL                                           |
| 1016       | Column family name is too short                                      |
| 1017       | Flush threshold is too low                                           |
| 1018       | Max level is too low                                                 |
| 1019       | Probability is too low                                               |
| 1020       | Failed to create new column family                                   |
| 1021       | Failed to add column family                                          |
| 1022       | Failed to lock column families lock                                  |
| 1024       | Failed to lock sstables lock                                         |
| 1025       | Failed to unlock sstables lock                                       |
| 1026       | Key is NULL                                                          |
| 1027       | Value is NULL                                                        |
| 1028       | Column family not found                                              |
| 1029       | Max threads is too low                                               |
| 1030       | Failed to lock sstables lock                                         |
| 1031       | Key not found                                                        |
| 1032       | Failed to create compaction thread                                   |
| 1033       | Failed to allocate memory for thread arguments                       |
| 1034       | Failed to deserialize bloom filter                                   |
| 1035       | Failed to initialize sstable cursor                                  |
| 1036       | Failed to read sstable                                               |
| 1037       | Failed to deserialize key value pair                                 |
| 1038       | Key value pair is NULL                                               |
| 1039       | Key not found                                                        |
| 1040       | Failed to signal flush condition                                     |
| 1041       | Failed to load column families                                       |
| 1042       | Failed to open wal                                                   |
| 1043       | Failed to destroy flush condition                                    |
| 1044       | Failed to destroy column families lock                               |
| 1045       | Failed to allocate memory for queue entry                            |
| 1046       | Failed to initialize flush mutex                                     |
| 1047       | Failed to initialize flush condition variable                        |
| 1048       | Failed to reallocate memory for column families                      |
| 1049       | Failed to append to wal                                              |
| 1050       | Failed to put into memtable                                          |
| 1051       | Not enough sstables to compact                                       |
| 1052       | Failed to allocate memory for transaction                            |
| 1053       | Failed to lock flush lock                                            |
| 1054       | Transaction is NULL                                                  |
| 1055       | Failed to read bloom filter                                          |
| 1056       | Failed to reallocate memory for transaction operations               |
| 1057       | Failed to allocate memory for cursor                                 |
| 1058       | Failed to initialize memtable cursor                                 |
| 1059       | Failed to initialize sstable cursor                                  |
| 1060       | Failed to get key value pair from cursor                             |
| 1061       | Cursor is NULL                                                       |
| 1062       | At end of cursor                                                     |
| 1063       | At start of cursor                                                   |
| 1064       | Key has a tombstone value.  To be deleted on next compaction         |
| 1065       | Key has expired.  To be deleted on next compaction                   |
| 1066       | Key's value cannot be a tombstone                                    |
| 1067       | Failed to allocate memory for wal                                    |
```

## License
Multiple
```
Mozilla Public License Version 2.0
BSD 2-Clause license
```