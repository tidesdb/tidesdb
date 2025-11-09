---
title: How does TidesDB work?
description: A high level description of how TidesDB works.
---

## 1. Introduction
TidesDB is a fast, efficient key-value storage engine library implemented in C, designed around the log-structured merge-tree (LSM-tree) paradigm. 

Rather than being a full-featured database management system, TidesDB serves as a foundational library that developers can use to build database systems or utilize directly as a standalone key-value or column store.

Here we explore the inner workings of TidesDB, its architecture, core components, and operational mechanisms.

## 2. Theoretical Foundation
### 2.1 Origins and Concept
The Log-Structured Merge-tree was first introduced by Patrick O'Neil, Edward Cheng, Dieter Gawlick, and Elizabeth O'Neil in their 1996 paper. The fundamental insight of the LSM-tree is to optimize write operations by using a multi-tier storage structure that defers and batches disk writes.

### 2.2 Basic LSM-tree Structure
An LSM-tree typically consists of multiple components

- In-memory buffers (memtables) that accept writes
- Immutable on-disk files (SSTables are Sorted String Tables)
- Processes that merge SSTables to reduce storage overhead and improve read performance

This structure allows for efficient writes by initially storing data in memory and then periodically flushing to disk in larger batches, reducing the I/O overhead associated with random writes.


## 3. TidesDB Architecture

<div class="architecture-diagram">

![Architecture Diagram](../../../assets/img2.png)

</div>

### 3.1 Overview
TidesDB uses a two-tiered storage architecture: a memory level that stores 
recently written key-value pairs in sorted order using a skip list data 
structure, and a disk level containing multiple SSTables. When reading data, 
newer tables take precedence over older ones, ensuring the most recent 
version of a key is always retrieved.

This design choice differs from other implementations like RocksDB and LevelDB, which use a multi-level approach with specific level-based compaction strategies.

### 3.2 Column Families
A distinctive aspect of TidesDB is its organization around column families. Each column family
<div class="architecture-diagram">

![Column Families](../../../assets/img3.png)

</div>

- Operates as an independent key-value store
- Has its own dedicated memtable and set of SSTables
- Can be configured with different parameters for flush thresholds, compression settings, etc.
- Uses read-write locks to allow concurrent reads but single-writer access

This design allows for domain-specific optimization and isolation between different types of data stored in the same database.

## 4. Core Components and Mechanisms
### 4.1 Memtable
<div class="architecture-diagram">

![Memtable](../../../assets/img4.png)

</div>

The memtable is an in-memory data structure that serves as the first landing 
point for all write operations. TidesDB implements the memtable as a lock-free 
skip list, using atomic operations and reference counting for concurrent access. 
Readers acquire references to the memtable before accessing it, while writers 
acquire an exclusive lock on the column family. Each column family can 
register a custom key comparison function (memcmp, string, numeric, or 
user-defined) that determines sort order consistently across the entire 
system--memtable, SSTables, and iterators all use the same comparison logic. 
The skip list's maximum level and probability parameters are configurable per 
column family, allowing tuning for specific workloads. When the memtable 
reaches a configurable size threshold, it becomes immutable and is queued for 
flushing while a new active memtable is created. The immutable memtable is 
flushed to disk as an SSTable by a background thread pool, with reference 
counting ensuring the memtable isn't freed until all readers complete and the 
flush finishes.

### 4.2 Block Manager Format

The block manager is TidesDB's low-level storage abstraction that manages both WAL files and SSTable files. All persistent data is stored using the block manager format.
<div class="architecture-diagram">

![Block Manager](../../../assets/img5.png)

</div>

#### File Structure

Every block manager file (WAL or SSTable) has the following structure

```
[File Header is 12 bytes]
[Block 0]
[Block 1]
[Block 2]
...
[Block N]
```

#### File Header (12 bytes)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 3 bytes | Magic | `0x544442` ("TDB" in hex) |
| 3 | 1 byte | Version | Block manager version (currently 1) |
| 4 | 4 bytes | Block Size | Default block size for this file |
| 8 | 4 bytes | Padding | Reserved for future use |

#### Block Format

Each block has the following structure

```
[Block Size is 8 bytes (uint64_t)]
[SHA1 Checksum is 20 bytes]
[Inline Data is a variable, up to block_size]
[Overflow Offset is 8 bytes (uint64_t)]
[Overflow Data is a variable, if size > block_size]
```

**Block Header (36 bytes minimum)**

The block header consists of the block size (8 bytes) representing the total size of the data (inline + overflow), an SHA1 checksum (20 bytes) for integrity checking the entire block data, inline data (variable) containing the first portion of data up to `block_size` bytes, and an overflow offset (8 bytes) pointing to overflow data (0 if no overflow).

**Overflow Handling**

If the data size is less than or equal to `block_size` (default 32KB), all data is stored inline with overflow offset set to 0. If the data size exceeds `block_size`, the first 32KB is stored inline and the remainder is placed at the overflow offset. Overflow data is written immediately after the main block, allowing efficient storage of both small and large blocks.

#### Block Write Process

The write process begins by computing the SHA1 checksum of the entire data, determining the inline size (minimum of data size and block_size), and calculating the remaining overflow size. The main block buffer is built containing the block size (8 bytes), SHA1 checksum (20 bytes), inline data (up to 32KB), and overflow offset (8 bytes, initially 0). The main block is written atomically using `pwrite()`. If overflow exists, the overflow data is written at the end of the file and the overflow offset in the main block is updated. Finally, fsync is optionally performed based on the sync mode.

#### Block Read Process

The read process reads the block size (8 bytes) and SHA1 checksum (20 bytes), calculates the inline size, and reads the inline data. It then reads the overflow offset (8 bytes). If the overflow offset is greater than 0, it seeks to the overflow offset and reads the remaining data. The inline and overflow data are concatenated, the SHA1 checksum is verified, and the block is returned if valid.

#### Integrity and Recovery
TidesDB implements multiple layers of data integrity protection. All block 
reads verify SHA1 checksums to detect corruption, while writes use `pwrite()` 
for atomic block-level updates. During startup, the system validates the last 
block's integrity--if corruption is detected, the file is automatically 
truncated to the last known-good block. This approach ensures crash safety by 
guaranteeing that incomplete or corrupted writes are identified and cleaned up 
during recovery.

#### Cursor Operations

The block manager provides cursor-based sequential access for efficient data 
traversal. Cursors support forward iteration via `cursor_next()` and backward 
iteration through `cursor_prev()`, which scans from the beginning to locate 
the previous block. Random access is available through `cursor_goto(pos)`, 
allowing jumps to specific file offsets. Each cursor maintains its current 
position and block size, with boundary checking methods like `at_first()`, 
`at_last()`, `has_next()`, and `has_prev()` to prevent out-of-bounds access.

#### Sync Modes

TDB_SYNC_NONE provides the fastest performance with no explicit fsync, relying on the OS page cache. TDB_SYNC_FULL offers the most durability by performing fsync after every block write. The sync mode is configurable per file, allowing WAL and SSTable files to have different modes.

#### Thread Safety

A write mutex serializes all write operations to prevent corruption, while concurrent reads are supported with multiple readers able to read simultaneously using `pread()`. All writes use `pwrite()` for atomic operations.

### 4.3 SSTables (Sorted String Tables)
SSTables serve as TidesDB's immutable on-disk storage layer. Internally, each 
SSTable is organized into multiple blocks containing sorted key-value pairs. 
To accelerate lookups, every SSTable maintains its minimum and maximum keys, 
allowing the system to quickly determine if a key might exist within it. 
Optional succinct trie indices provide direct access to specific blocks, 
eliminating the need to scan entire files. The immutable nature of SSTables--once 
written, they are never modified, only merged or deleted--ensures data consistency 
and enables lock-free concurrent reads.

**Reference Counting and Lifecycle**

SSTables use atomic reference counting to manage their lifecycle safely. When an 
SSTable is accessed (by a read operation, iterator, or compaction), its reference 
count is incremented. When the operation completes, the reference is released. 
Only when the reference count reaches zero is the SSTable actually freed from 
memory. This prevents use-after-free bugs during concurrent operations like 
compaction (which may delete SSTables) and reads (which may still be accessing them).

**Block Manager Caching**

The underlying block manager file handles are cached in a database-level LRU cache 
with a configurable capacity (`max_open_file_handles`). When an SSTable is opened, 
its block manager is added to the cache. If the cache is full, the least recently 
used block manager is automatically closed. This prevents file descriptor exhaustion 
while maintaining good performance for frequently accessed SSTables.

#### SSTable Block Layout

SSTables use the block manager format with sequential block ordering:

```
[File Header - 12 bytes Block Manager Header]
[Block 0: KV Pair 1]
[Block 1: KV Pair 2]
[Block 2: KV Pair 3]
...
[Block N-1: KV Pair N]
[Bloom Filter Block] (optional)
[Index Block] (optional)
[Metadata Block] (always last)
```

**Block Order (from first to last)**
1. **Data Blocks** - Key-value pairs in sorted order (sequential blocks starting at 0)
2. **Bloom Filter Block** (optional) - Only written if `enable_bloom_filter = 1`
3. **Index Block** (optional) - Only written if `enable_block_indexes = 1`
4. **Metadata Block** (required) - Always the last block in the file

**Note**: The exact block positions of bloom filter and index depend on how many KV pairs exist and which features are enabled. During SSTable loading, the system reads backwards from the end: metadata (last), then index (if present), then bloom filter (if present).

#### Data Block Format (KV Pairs)

Each data block contains a single key-value pair

```
[KV Header is 18 bytes (packed)]
[Key is variable]
[Value is variable]
```

**KV Pair Header (18 bytes, packed)**
```c
typedef struct __attribute__((packed)) {
    uint8_t version;        // Format version (currently 1)
    uint8_t flags;          // TDB_KV_FLAG_TOMBSTONE (0x01) for deletes
    uint32_t key_size;      // Key size in bytes
    uint32_t value_size;    // Value size in bytes
    int64_t ttl;            // Unix timestamp for expiration (0 = no expiration)
} tidesdb_kv_pair_header_t;
```

**Compression**
- If `enable_compression = 1` in column family config, entire block is compressed
- Compression applied to [Header + Key + Value] as a unit
- Supports Snappy, LZ4, or ZSTD algorithms (configured via `compression_algorithm`)
- Decompression happens on read before parsing header
- Default is enabled with LZ4 algorithm

#### Bloom Filter Block
<div class="architecture-diagram">

![Bloom Filter](../../../assets/img7.png)

</div>

Written after all data blocks (if enabled)
- Serialized bloom filter data structure
- Used to quickly determine if a key might exist in the SSTable
- Avoids unnecessary disk I/O for non-existent keys
- False positive rate configurable per column family (default 1%)
- Only written if `enable_bloom_filter = 1` in column family config
- Loaded third-to-last when reading backwards during SSTable recovery

#### Index Block (Succinct Trie)
<div class="architecture-diagram">

![Index Block](../../../assets/img6.png)

</div>

Written after bloom filter block (if enabled)
- Succinct trie data structure mapping keys to block offsets
- Enables direct block access without scanning
- Uses LOUDS (Level-Order Unary Degree Sequence) encoding for space efficiency
- Maps complete keys to file offsets: `[key] -> [block_offset]`
- Only written if `enable_block_indexes = 1` in column family config
- If disabled, falls back to linear scan through data blocks
- Supports prefix queries for efficient range scans
- Loaded second-to-last when reading backwards during SSTable recovery

#### Metadata Block

Always written as the last block in the file

```
[Magic is 4 bytes (0x5353544D = "SSTM")]
[Num Entries is 8 bytes (uint64_t)]
[Min Key Size is 4 bytes (uint32_t)]
[Min Key is variable]
[Max Key Size is 4 bytes (uint32_t)]
[Max Key is variable]
```

**Purpose**
- Magic number (0x5353544D = "SSTM") identifies this as a valid SSTable metadata block
- Min/max keys enable range-based SSTable filtering during reads
- Num entries tracks total KV pairs in SSTable (used to know when to stop reading data blocks)
- **Always loaded first** during SSTable recovery using `cursor_goto_last()` to read from end of file

#### SSTable Write Process

1. Create SSTable file and initialize bloom filter and succinct trie builder (if enabled)
2. Iterate through memtable in sorted order using skip list cursor
3. **For each KV pair**
   - Build KV header (18 bytes) + key + value
   - Optionally compress the entire block
   - Write as data block and record the file offset
   - Add key to bloom filter (if enabled)
   - Add key->offset mapping to succinct trie builder (if enabled)
   - Track min/max keys
4. Build the succinct trie from the builder (if enabled)
5. Serialize and write bloom filter block (if enabled)
6. Serialize and write succinct trie index block (if enabled)
7. Build and write metadata block with magic number, entry count, and min/max keys

#### SSTable Read Process

1. **Load SSTable** (recovery)
   - Open block manager file
   - Use `cursor_goto_last()` to seek to last block
   - Read and parse metadata block (validates magic number 0x5353544D)
   - Extract num_entries, min_key, and max_key from metadata
   - Use `cursor_prev()` to read previous block (index, if present)
   - Deserialize succinct trie index (if data is valid)
   - Use `cursor_prev()` to read previous block (bloom filter, if present)
   - Deserialize bloom filter (if data is valid)

2. **Lookup Key**
   - Check if key is within min/max range (quick rejection)
   - Check bloom filter if enabled (probabilistic rejection)
   - If block indexes enabled: query succinct trie for exact block offset
   - If block indexes disabled: linear scan through data blocks
   - Read block at offset
   - Decompress block if compression is enabled
   - Parse KV header (18 bytes) and extract key/value
   - Check TTL expiration
   - Return value or tombstone marker

SSTables are read from storage engine level LRU.
<div class="architecture-diagram">

![LRU](../../../assets/img8.png)

</div>

### 4.4 Write-Ahead Log (WAL)
For durability, TidesDB implements a write-ahead logging mechanism with a rotating WAL system tied to memtable lifecycle.

#### 4.4.1 WAL File Naming and Lifecycle
<div class="architecture-diagram">

   ![WAL/Memtable Lifecycle](../../../assets/img9.png)
   
</div>

File Format: `wal_<memtable_id>.log`

WAL files follow the naming pattern `wal_0.log`, `wal_1.log`, `wal_2.log`, etc. Each memtable has its own dedicated WAL file, with the WAL ID matching the memtable ID (a monotonically increasing counter). Multiple WAL files can exist simultaneously—one for the active memtable and others for memtables in the flush queue. WAL files are deleted only after the memtable is successfully flushed to an SSTable and freed.

#### 4.4.2 WAL Rotation Process

TidesDB uses a rotating WAL system that works as follows:

Initially, the active memtable (ID 0) uses `wal_0.log`. When the memtable size reaches `memtable_flush_size`, rotation is triggered. During rotation, a new active memtable (ID 1) is created with `wal_1.log`, while the immutable memtable (ID 0) with `wal_0.log` is added to the immutable memtables queue. A flush task is submitted to the flush thread pool. The background flush thread writes memtable (ID 0) to `sstable_0.sst` while `wal_0.log` still exists. Once the flush completes successfully, the memtable is dequeued from the immutable queue, its reference count drops to zero, and both the memtable and `wal_0.log` are freed/deleted. Multiple memtables can be in the flush queue concurrently, each with its own WAL file and reference count.

#### 4.4.3 WAL Features

All writes (including deletes/tombstones) are first recorded in the WAL before being applied to the memtable. WAL entries can be optionally compressed using Snappy, LZ4, or ZSTD. Each column family maintains its own independent WAL files, and automatic recovery on database startup reconstructs memtables from WALs.

#### 4.4.4 Recovery Process

On database startup, TidesDB automatically recovers from WAL files:

The system scans the column family directory for `wal_*.log` files and sorts them by ID (oldest to newest). It then replays each WAL file into a new memtable, reconstructing the in-memory state from persisted WAL entries before continuing normal operation with the recovered data.

**What Gets Recovered**

All committed transactions that were written to WAL are recovered. Uncommitted transactions are discarded (as they're not in the WAL), along with memtables that were being flushed when the crash occurred.

**SSTable Recovery Ordering**

SSTables are discovered by reading the column family directory, where directory order is filesystem-dependent and non-deterministic. SSTables are sorted by ID after loading to ensure correct read semantics, guaranteeing newest-to-oldest ordering for the read path (which searches from the end of the array backwards). Without sorting, stale data could be returned if newer SSTables load before older ones.

### 4.5 Bloom Filters
To optimize read operations, TidesDB employs Bloom filters--probabilistic data 
structures that quickly determine if a key might exist in an SSTable. By 
filtering out SSTables that definitely don't contain a key, Bloom filters help 
avoid unnecessary disk I/O. Each Bloom filter is configurable per column 
family to balance memory usage against read performance. The bloom filter is 
serialized and stored as the second-to-last block in the SSTable file, just 
before the index block.

## 5. Data Operations
### 5.1 Write Path
When a key-value pair is written to TidesDB

1. The operation is recorded in the active memtable's WAL
2. The key-value pair is inserted into the active memtable's skip list
3. The memtable size is checked after each write
4. If the memtable size exceeds the flush threshold (`memtable_flush_size`)

- The current memtable becomes immutable and is added to the flush queue
- A new active memtable is created with a new WAL file
- The immutable memtable is submitted to the flush thread pool
- Background threads flush the immutable memtable to an SSTable
- After successful flush, the WAL file is deleted and the memtable is freed
- Writes continue immediately to the new active memtable without blocking


### 5.2 Read Path
When reading a key from TidesDB

1. First, the active memtable is checked for the key
2. If not found, immutable memtables in the flush queue are checked (newest to oldest)
3. If still not found, SSTables are checked in reverse chronological order (newest to oldest)
4. For each SSTable:
   - Check if key is within min/max key range (quick rejection)
   - If within range, check bloom filter (if enabled) to determine if key might exist
   - If bloom filter indicates possible match (or if disabled):
     - If block indexes enabled: query succinct trie for exact block offset
     - If block indexes disabled: linear scan through data blocks
   - Read the block at the determined offset
   - Decompress block if compression is enabled
   - Parse KV header and compare keys
   - Check TTL expiration and tombstone flag
5. The search stops when the key is found or all sources have been checked
6. Return the value or TDB_ERR_NOT_FOUND

### 5.3 Transactions
TidesDB provides ACID transaction support with multi-column-family 
capabilities. Transactions are initiated through `tidesdb_txn_begin()` for 
writes or `tidesdb_txn_begin_read()` for read-only operations, with a single 
transaction capable of operating atomically across multiple column families. 
The system implements read committed isolation, where read transactions see a 
consistent snapshot via copy-on-write without blocking writers. Write 
transactions acquire exclusive locks per column family only during commit, 
ensuring atomicity--all operations succeed together or automatically rollback 
on failure. Transactions support read-your-own-writes semantics, allowing 
uncommitted changes to be read before commit. The API uses simple integer 
return codes (0 for success, -1 for error) rather than complex error 
structures.

### 6. Compaction Strategies
TidesDB implements two distinct compaction strategies

### 6.1 Parallel Compaction

TidesDB implements parallel compaction using semaphore-based thread limiting to 
reduce SSTable count, remove tombstones, and purge expired TTL entries. The 
number of concurrent threads is configurable via `compaction_threads` in the 
column family config (default 4). Compaction pairs SSTables from oldest to 
newest (pairs 0+1, 2+3, 4+5, etc.), with each thread processing one pair. A 
semaphore limits concurrent threads to the configured maximum. When 
`compaction_threads >= 2`, `tidesdb_compact()` automatically uses parallel 
execution. At least 2 SSTables are required to trigger compaction. The process 
approximately halves the SSTable count per run.

### 6.2 Background Compaction

Background compaction provides automatic, hands-free SSTable management. 
Enabled via `enable_background_compaction = 1` in the column family 
configuration, it automatically triggers when the SSTable count reaches 
`max_sstables_before_compaction`. When a flush completes and the SSTable count 
exceeds the threshold, a compaction task is submitted to the database-level 
compaction thread pool. This operates independently without blocking application 
operations, merging SSTable pairs incrementally throughout the database lifecycle 
until shutdown. The interval between compaction checks is configurable via 
`background_compaction_interval` (default 1 second).

### 6.3 Compaction Mechanics

During compaction, SSTables are paired (typically oldest with second-oldest) and merged into new SSTables. For each key, only the newest version is retained, while tombstones (deletion markers) and expired TTL entries are purged. Original SSTables are deleted after a successful merge. If a merge is interrupted, the system will clean up after on restart without causing corruption.

## 7. Performance Optimizations
### 7.1 Block Indices

TidesDB employs block indices to optimize read performance. Each SSTable contains an optional final block with a succinct trie block index, which allows direct access to the block containing a specific key or key prefix and significantly reduces I/O by avoiding full SSTable scans.

### 7.2 Compression

TidesDB supports multiple compression algorithms: Snappy emphasizes speed over compression ratio, LZ4 provides a balanced approach with good speed and reasonable compression, and ZSTD offers a higher compression ratio at the cost of some performance. Compression can be applied to both SSTable entries and WAL entries.

### 7.3 Sync Modes

TidesDB provides two sync modes to balance durability and performance. TDB_SYNC_NONE is fastest but least durable, relying on the OS to handle flushing to disk via page cache. TDB_SYNC_FULL is most durable, performing fsync on every write operation. The sync mode can be configured per column family, allowing different durability guarantees for different data types.

### 7.4 Configurable Parameters

TidesDB allows fine-tuning through various configurable parameters including memtable flush thresholds, skip list configuration (max level and probability), bloom filter usage and false positive rate, compression settings (algorithm selection), compaction trigger thresholds and thread count, sync mode (TDB_SYNC_NONE or TDB_SYNC_FULL), debug logging, succinct trie block index usage, and thread pool sizes (flush and compaction).

### 7.5 Thread Pool Architecture

For efficient resource management, TidesDB employs shared thread pools at the 
database level. Rather than maintaining separate pools per column family, all 
column families share common flush and compaction thread pools configured 
during database initialization. Operations are submitted as tasks to these 
pools, enabling non-blocking execution--application threads can continue 
processing while flush and compaction work proceeds in the background. This 
architecture minimizes resource overhead and provides consistent, predictable 
performance across the entire database.

**Configuration**
```c
tidesdb_config_t config = {
    .db_path = "./mydb",
    .num_flush_threads = 4,      /* 4 threads for flush operations */
    .num_compaction_threads = 8  /* 8 threads for compaction */
};
```

**Thread Pool Implementation**

Each thread pool consists of worker threads that wait on a task queue. When a 
task is submitted (flush or compaction), it's added to the appropriate queue 
and a worker thread picks it up. The flush pool handles memtable-to-SSTable 
flush operations, while the compaction pool handles SSTable merge operations. 
Worker threads use `queue_dequeue_wait()` to block efficiently when no tasks 
are available, waking immediately when work arrives.

**Benefits**

One set of threads serves all column families providing resource efficiency, with better thread utilization across workloads. Configuration is simpler since it's set once at the database level, and the system is easily scalable to tune for available CPU cores. The queue-based design prevents thread creation overhead and enables graceful shutdown.

**Default values**

The `num_flush_threads` defaults to 2 (TDB_DEFAULT_THREAD_POOL_SIZE) and is I/O bound, so 2-4 is usually sufficient. The `num_compaction_threads` also defaults to 2 (TDB_DEFAULT_THREAD_POOL_SIZE) but is CPU bound, so it can be set higher (4-16).

## 8. Concurrency and Thread Safety

TidesDB is designed for great concurrency with minimal blocking through a reader-writer lock model.

### 8.1 Reader-Writer Locks

Each column family uses a reader-writer lock to enable efficient concurrent 
access. Multiple readers can access the same column family simultaneously 
without blocking each other, and read operations can proceed even while writes 
are in progress. However, writers acquire exclusive access, allowing only one 
write transaction per column family at a time to ensure data consistency.

### 8.2 Transaction Isolation

TidesDB implements read committed isolation with read-your-own-writes 
semantics. Read transactions acquire read locks and see a consistent snapshot 
of committed data through copy-on-write, ensuring they never observe 
uncommitted changes from other transactions. Write transactions acquire write 
locks only during commit to ensure atomic updates. Within a single 
transaction, uncommitted changes are immediately visible, allowing operations 
to read their own writes before commit.

### 8.3 Optimal Use Cases

This concurrency model makes TidesDB particularly well-suited for

- **Read-heavy workloads** Unlimited concurrent readers with no contention
- **Mixed read/write workloads** Readers never wait for writers to complete
- **Multi-column-family applications** Different column families can be written to concurrently

## 9. Directory Structure and File Organization

TidesDB organizes data on disk with a clear directory hierarchy. Understanding this structure is essential for backup, monitoring, and debugging.

### 9.1 Database Directory Layout

Each TidesDB database has a root directory containing subdirectories for each column family

```
mydb/
├── my_cf/
│   ├── config.cfc         # Persisted column family configuration
│   ├── wal_1.log
│   ├── sstable_0.sst
│   ├── sstable_1.sst
│   └── sstable_2.sst
├── users/
│   ├── config.cfc
│   ├── wal_0.log
│   └── sstable_0.sst
└── sessions/
    ├── config.cfc
    └── wal_0.log
```

### 9.2 File Naming Conventions

#### Write-Ahead Log (WAL) Files
Write-Ahead Log (WAL) files follow the naming convention `wal_<memtable_id>.log` 
(e.g., `wal_0.log`, `wal_1.log`) and provide durability by recording all 
writes before they're applied to the memtable. Each memtable has its own 
dedicated WAL file with a matching ID based on a monotonically increasing 
counter. WAL files are created when a new memtable is created--either on 
database open or during memtable rotation--and multiple WAL files can exist 
simultaneously: one for the active memtable and others for memtables in the 
flush queue. A WAL file is deleted only after its corresponding memtable is 
successfully flushed to an SSTable and freed from memory. If a flush doesn't 
complete before shutdown, the WAL is automatically recovered on the next 
database restart, replaying operations to restore consistency.

#### SSTable Files
SSTable files follow the naming convention `sstable_<sstable_id>.sst` (e.g., 
`sstable_0.sst`, `sstable_1.sst`) and provide persistent storage for flushed 
memtables. An SSTable is created when a memtable exceeds the 
`memtable_flush_size` threshold, with IDs assigned using a monotonically 
increasing counter per column family. Each SSTable contains sorted key-value 
pairs along with bloom filter and index metadata for efficient lookups. During 
compaction, old SSTables are merged into new consolidated files, and the 
original SSTables are deleted after the merge completes successfully.

### 9.3 WAL Rotation and Memtable Lifecycle Example

This example demonstrates how WAL files are created, rotated, and deleted

**1. Initial State**
```
Active Memtable (ID 0) → wal_0.log
```

**2. Memtable Fills Up** (size >= `memtable_flush_size`)
```
Active Memtable (ID 0) → wal_0.log  [FULL - triggers rotation]
```

**3. Rotation Occurs**
```
New Active Memtable (ID 1) → wal_1.log  [new WAL created]
Immutable Memtable (ID 0) → wal_0.log  [queued for flush]
```

**4. Background Flush (Async)**
```
Active Memtable (ID 1) → wal_1.log
Flushing Memtable (ID 0) → sstable_0.sst  [writing to disk]
wal_0.log  [still exists - flush in progress]
```

**5. Flush Complete**
```
Active Memtable (ID 1) → wal_1.log
sstable_0.sst  [persisted]
wal_0.log  [DELETED - memtable freed after flush]
```

**6. Next Rotation (Before Previous Flush Completes)**
```
New Active Memtable (ID 2) → wal_2.log  [new active]
Immutable Memtable (ID 1) → wal_1.log  [queued for flush]
Flushing Memtable (ID 0) → sstable_0.sst  [still flushing]
wal_0.log  [still exists - flush not complete]
```

**7. After All Flushes Complete**
```
Active Memtable (ID 2) → wal_2.log
SSTable sstable_0.sst
SSTable sstable_1.sst
wal_0.log, wal_1.log  [DELETED means both flushes complete]
```

### 9.4 Directory Management

**Creating a column family** creates a new subdirectory
```c
tidesdb_create_column_family(db, "my_cf", &cf_config);
// Creates mydb/my_cf/ directory with
//   - initial wal_0.log (for active memtable)
//   - config.cfc (persisted configuration)
```

**Dropping a column family** removes the entire subdirectory
```c
tidesdb_drop_column_family(db, "my_cf");
// Deletes mydb/my_cf/ directory and all contents (WALs, SSTables)
```

### 9.5 Monitoring Disk Usage

Useful commands for monitoring TidesDB storage

```bash
# Check total database size
du -sh mydb/

# Check per-column-family size
du -sh mydb/*/

# Count WAL files (should be 1-2 per CF normally)
find mydb/ -name "wal_*.log" | wc -l

# Count SSTable files
find mydb/ -name "sstable_*.sst" | wc -l

# List largest SSTables
find mydb/ -name "sstable_*.sst" -exec ls -lh {} \; | sort -k5 -hr | head -10
```

### 9.6 Best Practices

**Disk Space Monitoring**

Monitor WAL file count, which is typically 1-3 per column family (1 active + 1-2 in flush queue). Many WAL files (>5) may indicate a flush backlog, slow I/O, or configuration issue. Monitor SSTable count as it triggers compaction at `max_sstables_before_compaction`. Set appropriate `memtable_flush_size` based on write patterns and flush speed.

**Backup Strategy**
```bash
# Stop writes, flush all memtables, then backup
# In your application
tidesdb_flush_memtable(cf);  # Force flush before backup

# Then backup
tar -czf mydb_backup.tar.gz mydb/
```

**Performance Tuning**

Larger `memtable_flush_size` results in fewer, larger SSTables with less compaction, while smaller `memtable_flush_size` creates more, smaller SSTables with more compaction. Adjust `max_sstables_before_compaction` based on your read/write ratio, and use `enable_background_compaction` for automatic maintenance.

## 10. Error Handling

TidesDB uses simple integer return codes for error handling. A return value of `0` (TDB_SUCCESS) indicates a successful operation, while negative values indicate specific error conditions. Error codes include memory allocation failures, I/O errors, corruption detection, lock failures, and more, allowing for precise error handling in production systems.

For a complete list of error codes and their meanings, see the [Error Codes Reference](../../reference/error-codes).

## 11. Memory Management
If a key value pair exceeds `TDB_MEMORY_PERCENTAGE` which is 60% of the available memory on your system TidesDB will throw a `TDB_ERR_MEMORY_LIMIT` error. This is to prevent the system from running out of memory or haulting.