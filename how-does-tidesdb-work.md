---
title: How does TidesDB work?
description: A comprehensive design overview of TidesDB's architecture, core components, and operational mechanisms.
---

## Introduction

TidesDB is an embeddable key-value storage engine built on log-structured merge trees (LSM trees). LSM trees optimize for write-heavy workloads by batching writes in memory and flushing sorted runs to disk. This trades write amplification (data written multiple times during compaction) for improved write throughput and sequential I/O patterns. The fundamental tradeoff: writes are fast but reads must search multiple sorted files.

The system provides ACID transactions with five isolation levels and manages data through a hierarchy of sorted string tables (SSTables). Each level holds roughly N× more data than the previous level. Compaction merges SSTables from adjacent levels, discarding obsolete entries and reclaiming space.

Data flows from memory to disk in stages. Writes go to an in-memory skip list (chosen over AVL trees for lock-free reads and simpler implementation) backed by a write-ahead log. When the skip list exceeds the set write buffer size, it becomes immutable and a background worker flushes it to disk as an SSTable. These tables accumulate in levels. Compaction merges tables from adjacent levels, maintaining the level size invariant.

## Data Model

### Column Families

The database organizes data into column families. Each column family is an independent key-value namespace with its own configuration, memtables, write-ahead logs, and disk levels. This isolation allows different column families to use different compression algorithms, comparators, and tuning parameters within the same database instance.

A column family maintains:

- One active memtable for new writes
- A queue of immutable memtables awaiting flush to disk
- A write-ahead log paired with each memtable
- Up to 32 levels of sorted string tables on disk
- A manifest file tracking which SSTables belong to which levels

### Sorted String Tables

Each sorted string table (SSTable) consists of two files: a key log (.klog) and a value log (.vlog). The key log stores keys, metadata, and values smaller than the configured threshold (default 4KB). Values exceeding this threshold reside in the value log, with the key log storing only file offsets. This separation keeps the key log compact for efficient scanning while accommodating arbitrarily large values.

The key log uses a block-based format. Each block (fixed at 64KB) contains multiple entries serialized with variable-length integer encoding. Blocks compress independently using LZ4, Zstd, or Snappy. The key log ends with three auxiliary structures: a block index for binary search, a bloom filter for negative lookups, and a metadata block with SSTable statistics.

### File Format

Each klog entry uses this format:
```
flags (1 byte)
key_size (varint)
value_size (varint)
seq (varint)
ttl (8 bytes, if HAS_TTL flag set)
vlog_offset (varint, if HAS_VLOG flag set)
key (key_size bytes)
value (value_size bytes, if inline)
```

The flags byte encodes tombstones (0x01), TTL presence (0x02), value log indirection (0x04), and delta sequence encoding (0x08). Variable-length integers save space: a value under 128 requires one byte, while the full 64-bit range needs at most ten bytes.

Write-ahead logs use the same format. Each memtable has its own WAL file, named by the SSTable ID it will become. Recovery reads these files in sequence order, deserializes entries into skip lists, and enqueues them for asynchronous flushing.

## Transactions

### Isolation Levels

The system provides five isolation levels:

**Read Uncommitted** sees all versions, including uncommitted ones. The snapshot sequence is set to UINT64_MAX.

**Read Committed** performs no validation. Each read refreshes its snapshot to see the most recently committed version.

**Repeatable Read** detects if any read key changed between read and commit time. The transaction tracks each key it reads along with the sequence number of the version it saw. At commit, it checks whether a newer version exists.

**Snapshot Isolation** additionally checks for write-write conflicts. If another transaction committed a write to the same key after this transaction's snapshot time, the commit aborts.

**Serializable** implements serializable snapshot isolation (SSI). The system tracks read-write conflicts:

1. Each transaction maintains a read set (arrays of CF pointers, keys, key sizes, sequence numbers)
2. When read set exceeds threshold (default 64 entries), creates a hash table (`tidesdb_read_set_hash_t`) using xxHash for O(1) conflict detection
3. At commit, checks all concurrent transactions: if transaction T reads key K that another transaction T' writes, sets `T.has_rw_conflict_out = 1` and `T'.has_rw_conflict_in = 1`
4. If both flags are set (transaction is a pivot in dangerous structure), aborts

This is simplified SSI - it detects pivot transactions but does not maintain a full precedence graph or perform cycle detection. False aborts are possible when non-pivot transactions have both flags set.

### Multi-Version Concurrency Control

Each transaction receives a snapshot sequence number at begin time. For Read Uncommitted, this is UINT64_MAX (sees all versions). For Read Committed, it refreshes on each read. For Repeatable Read, Snapshot, and Serializable, the snapshot is `global_seq - 1`, capturing all transactions committed before this one started.

The snapshot sequence determines which versions the transaction sees: it reads the most recent version with sequence number less than or equal to its snapshot sequence.

At commit time, the system assigns a commit sequence number from a global atomic counter. It writes operations to the write-ahead log, applies them to the active memtable with the commit sequence, and marks the sequence as committed in a fixed-size buffer (hardcoded at 65536 entries). The buffer wraps around: sequence N maps to slot N % 65536. This limits the maximum sequence number gap between oldest active transaction and newest commit to 65536. Long-running transactions may cause commits to stall waiting for buffer space. Readers skip versions whose sequence numbers are not yet marked committed.

## Write Path

### Transaction Commit

A transaction buffers operations in memory until commit. At commit time:

1. The system validates according to isolation level
2. It assigns a commit sequence number from the global counter
3. It serializes operations to each column family's write-ahead log
4. It applies operations to the active memtable with the commit sequence
5. It marks the commit sequence as committed in the status buffer
6. It checks if any memtable exceeds its size threshold

The transaction uses hash-based deduplication (simple multiplicative hash: `hash = hash * 31 + key[i]`) to apply only the final operation for each key. This is a fast non-cryptographic hash - collisions are possible but rare, and would cause the transaction to write both operations to the memtable (skip list handles duplicates correctly). This optimization reduces memtable size when a transaction modifies the same key multiple times.

### Memtable Flush

When a memtable exceeds its configured size (default 64MB), the system atomically swaps in a new empty memtable and enqueues the old one for flushing. The swap takes one atomic store with a memory fence for visibility.

A flush worker dequeues the immutable memtable and creates an SSTable. It iterates the skip list in sorted order, writing entries to 64KB blocks. Values exceeding the threshold (default 4KB) go to the value log; the key log stores only the file offset. The worker compresses each block, writes the block index and bloom filter, and appends metadata. It then fsyncs both files, adds the SSTable to level 1, commits to the manifest, and deletes the write-ahead log.

The ordering is critical: fsync before manifest commit ensures the SSTable is durable before it becomes discoverable. Manifest commit before WAL deletion ensures crash recovery can find the data.

**Crash scenarios** · If the system crashes after fsync but before manifest commit, the SSTable exists on disk but is not discoverable - it becomes garbage and the reaper eventually deletes it. If it crashes after manifest commit but before WAL deletion, recovery finds both the SSTable and the WAL - it flushes the WAL again, creating a duplicate SSTable. The manifest deduplicates by SSTable ID.

**Permissive validation** · WAL files use `block_manager_validate_last_block(bm, 0)` (permissive mode). If the last block has invalid footer magic or incomplete data, the system truncates the file to the last valid block by walking backward through the file. This handles crashes during WAL writes. If no valid blocks exist, truncates to header only.

**Strict validation** · SSTables use `block_manager_validate_last_block(bm, 1)` (strict mode). Any corruption in the last block causes the SSTable to be rejected entirely. This reflects that SSTables are permanent and must be correct.

### L0 Throttling and Backpressure

When writes arrive faster than flush workers can persist memtables to disk, immutable memtables accumulate in the flush queue. Without throttling, this causes unbounded memory growth. The system implements graduated backpressure based on the L0 immutable queue depth and L1 file count.

Each column family maintains a queue of immutable memtables awaiting flush. When the active memtable exceeds its size threshold, it becomes immutable and enters this queue. A flush worker dequeues it asynchronously and writes it to an SSTable at level 1. The queue depth indicates how far behind the flush workers are.

**Throttling thresholds** · The system monitors two metrics:

1. **L0 queue depth** - number of immutable memtables in the flush queue (configurable threshold, default 10)
2. **L1 file count** - number of SSTables at level 1 (configurable trigger, default 4)

**Graduated backpressure** · The system applies increasing delays to write operations based on pressure:

**Moderate pressure** (30% of stall threshold or 2× L1 trigger) - Writes sleep for 1ms. This gently slows the write rate without significantly impacting throughput. At 30% of the default threshold (3 immutable memtables), writes experience minimal latency increase.

**High pressure** (60% of stall threshold or 3× L1 trigger) - Writes sleep for 5ms. This more aggressively reduces write throughput to give flush and compaction workers time to catch up. At 60% of the default threshold (6 immutable memtables), write latency increases noticeably but writes continue.

**Stall** (≥100% of stall threshold) - Writes block completely until the queue drains below the threshold. The system checks queue depth every 10ms, waiting up to 10 seconds before timing out with an error. This prevents memory exhaustion when flush workers cannot keep pace. At the default threshold (10 immutable memtables), all writes stall until flush workers reduce the queue depth.

**Coordination with L1** · The backpressure mechanism considers both L0 queue depth and L1 file count. High L1 file count indicates compaction is falling behind, which will eventually slow flush operations (flush workers must wait for compaction to free space). By throttling writes based on L1 file count, the system prevents cascading backlog.

**Memory protection** · Each immutable memtable holds the full contents of a flushed memtable (default 64MB). With a stall threshold of 10, the system allows up to 640MB of immutable memtables plus the active memtable (64MB) before blocking writes. This bounds memory usage to roughly 704MB per column family under maximum write pressure, preventing out-of-memory conditions.

**Worker coordination** · The throttling mechanism assumes flush workers are making progress. If the queue depth remains at or above the stall threshold for 10 seconds (1000 iterations × 10ms), the system returns an error indicating the flush worker may be stuck. This typically indicates disk I/O failure, insufficient disk space, or a deadlock in the flush path.

**Configuration interaction** · Increasing `write_buffer_size` reduces flush frequency but increases memory usage during stalls. Increasing `l0_queue_stall_threshold` allows more memory usage but provides more buffering for bursty workloads. Increasing flush worker count reduces queue depth under sustained write load. The optimal configuration depends on write patterns, available memory, and disk throughput.

## Read Path

### Search Order

A read searches for a key in order:

1. Active memtable
2. Immutable memtables (newest to oldest)
3. SSTables in level 1
4. SSTables in level 2, then 3, and so on

The search stops at the first occurrence. Since newer data resides in earlier locations, this finds the most recent version.

### SSTable Lookup

For each SSTable, the system:

1. Checks min/max key bounds using the column family's comparator
2. If bloom filter exists (`enable_bloom_filter=1`), checks it. If negative, the key is definitely absent.
3. If block index exists (`enable_block_indexes=1`), finds which block might contain the key
4. Initializes a cursor at the block index hint (if available) or at the first block
5. For each block:
   - If block cache exists, generates cache key from column family name, SSTable ID, and block offset
   - On cache hit, increments reference count and uses cached block
   - On cache miss, reads block from disk, decompresses if needed, deserializes, and caches it
   - Binary searches the block for the key
6. If found and the entry has a vlog offset, reads the value from the value log

The bloom filter (default 1% FPR) and block index are optional optimizations configured per column family.

**Bloom filter false positive cost** · A false positive requires: (1) bloom filter check (memory access), (2) block index lookup (likely cache miss = disk read), (3) block read and deserialize (cache miss = disk read), (4) binary search block (memory). That's 2 disk reads for a key that doesn't exist. With 1% FPR and high query rate, this adds significant I/O.

The block cache uses a clock eviction policy with reference counting. Multiple readers share cached blocks without copying. The clock hand skips blocks with refcount > 1 (actively in use). When the cache evicts a block, it decrements the reference count; the block frees when the count reaches zero.

### Block Index

The block index enables fast key lookups by mapping key ranges to file offsets. Instead of scanning all blocks sequentially, the system uses binary search on the index to jump directly to the block that might contain the key.

**Structure** · The index stores three parallel arrays:
- `min_key_prefixes` · First key prefix of each indexed block (configurable length, default 16 bytes)
- `max_key_prefixes` · Last key prefix of each indexed block
- `file_positions` · File offset where each block starts

**Sparse Sampling** · The `index_sample_ratio` (default 1) controls how many blocks to index. A ratio of 1 indexes every block; a ratio of 10 indexes every 10th block. Sparse indexing reduces memory usage at the cost of potentially scanning multiple blocks on lookup.

**Prefix Compression** · Keys are stored as fixed-length prefixes (default 16 bytes, configurable via `block_index_prefix_len`). Keys shorter than the prefix length are zero-padded. This trades precision for space - keys with identical prefixes may require scanning multiple blocks to disambiguate.

**Binary Search Algorithm** · `compact_block_index_find_predecessor()` finds the rightmost block where `min_key <= search_key <= max_key`:

1. Create search key prefix (pad with zeros if shorter than prefix length)
2. Early exit if search key < first block's min key (return first block)
3. Binary search for blocks where `min_key <= search_key <= max_key`
4. Return the rightmost matching block (handles keys at block boundaries)
5. If no exact match, return the last block where `min_key <= search_key`

This ensures the search always starts from the correct block, avoiding false negatives when keys fall between indexed blocks.

**Serialization** · The index serializes compactly using delta encoding for file positions (varints) and raw prefix bytes. Format: `varint(count)`, `varint(prefix_len)`, delta-encoded file positions, min key prefixes, max key prefixes. This achieves ~50% space savings compared to storing absolute positions.

**Custom Comparators** · The index supports pluggable comparator functions, allowing column families with custom key orderings (uint64, lexicographic, reverse, etc.) to use block indexes correctly.

**Memory Usage** · For an SSTable with 1000 blocks and default 16-byte prefixes: 32KB for prefixes + 8KB for positions = 40KB. With sparse sampling (ratio 10), this reduces to 4KB. The index is loaded into memory when an SSTable is opened and remains resident.

**Usage in Seeks and Iteration** · Block indexes are also used by iterator seek operations (`tidesdb_iter_seek()` and `tidesdb_iter_seek_for_prev()`). When seeking to a key:

1. The bloom filter is checked first (eliminates 99% of negative lookups)
2. The block index finds the predecessor block using binary search
3. The cursor jumps directly to that block position
4. The iterator scans forward (or backward for `seek_for_prev`) from there

This optimization is critical for range queries - without block indexes, seeking to a key in the middle of a large SSTable would require scanning all blocks from the beginning. With block indexes, the seek operation is O(log N) on the index plus O(M) scanning a few blocks, rather than O(N×M) scanning all blocks.

## Compaction

### Compaction Policies

The system employs three policies based on the Spooky paper:

**Full preemptive merge** combines all SSTables from two adjacent levels into the target level. Simple but generates large temporary files.

**Dividing merge** merges levels 1 through X into level X+1. If X is the largest level, it first calls DCA to add a new level, then performs the merge. This reduces temporary space by spreading output across the level structure.

**Partitioned merge** divides the key space into ranges and merges each range independently. This produces smaller output files and enables parallel compaction.

### Compaction Triggers

Compaction triggers when level 1 accumulates a threshold number of SSTables (default 4) or when a level exceeds its capacity. Each level has capacity N× the previous level (configurable ratio, default 10×).

### Dynamic Capacity Adaptation

DCA is separate from compaction policies. Compaction policies (full/dividing/partitioned) determine how to merge data. DCA determines when to add or remove levels from the structure.

**Level Addition** · Triggered by dividing merge when merging into the largest level, or by compaction when a level exceeds capacity. The system:
1. Creates a new empty level with capacity = previous_largest_capacity × ratio
2. Atomically increments `num_active_levels`
3. Lets normal compaction move data down (does not move data during addition to avoid key loss)

**Level Removal** · Triggered after compaction when the largest level becomes completely empty. The system:
1. Checks if `num_active_levels > min_levels` (configurable, default 5, prevents thrashing)
2. Frees the empty level
3. Updates new largest level capacity: `new_capacity = old_capacity / ratio`
4. Atomically decrements `num_active_levels`
5. Calls `tidesdb_apply_dca()` to rebalance

**Capacity Rebalancing** · `tidesdb_apply_dca()` runs after level removal. It updates all level capacities using `C[i] = N_L / T^(L-1-i)` where:
- `N_L` = current size of largest level
- `T` = level size ratio
- `L` = number of levels
- `i` = level index (0-based)

This ensures capacities remain proportional to actual data distribution. Without rebalancing, intermediate levels would have stale capacities after removal.

**Initialization** · Column families start with `min_levels` (configurable, default 5) pre-allocated. If recovery finds SSTables at level N > min_levels, initializes with N levels (e.g., finds level 8 SSTables → initializes with 8 levels). If recovery finds SSTables at level N < min_levels, still initializes with min_levels (e.g., finds level 3 SSTables → initializes with 5 levels, leaving levels 4-5 empty). The floor prevents small databases from thrashing between 2-3 levels and guarantees predictable read performance.

### Merge Process

During compaction:

1. The system opens all source SSTables and creates merge sources
2. It builds a min-heap (`tidesdb_merge_heap_t`) with elements `tidesdb_merge_source_t*` containing:
   - Source type (memtable or SSTable)
   - Current key-value pair (`current_kv`)
   - Cursor for iterating source (skip list cursor or block manager cursor)
3. It pops the minimum element, advances that source's cursor to the next entry, and sifts down
4. It discards tombstones, expired TTL entries, and duplicates (keeping newest by sequence number)
5. It writes surviving entries to new SSTables in blocks (64KB each)
6. It fsyncs the new SSTables
7. It commits them to the manifest
8. It marks old SSTables for deletion

If a source encounters corruption during advance, `tidesdb_merge_heap_pop()` returns the corrupted SSTable for deletion and removes that source from the heap.

Large values flow through compaction: the system reads from the source value log, recompresses according to current configuration, and writes to the destination value log. This allows compression settings to change over time.

## Recovery

On startup, the system scans each column family directory for write-ahead logs and SSTables. It reads the manifest file to determine which SSTables belong to which levels.

For each write-ahead log, ordered by sequence number:

1. It opens the log file
2. It validates the file, truncating partial writes at the end (permissive mode)
3. It deserializes entries into a new skip list with the correct comparator
4. It enqueues the skip list for asynchronous flushing

The manifest tracks the maximum sequence number across all SSTables. Recovery updates the global sequence counter to one past this maximum, ensuring new transactions receive higher sequence numbers than any existing data.

For SSTables, the system uses strict validation, rejecting any corruption. This reflects the different roles: logs are temporary and rebuilt on recovery; SSTables are permanent and must be correct.

## Background Workers

Four worker pools handle asynchronous operations:

**Flush workers** (configurable, default 2 threads) dequeue immutable memtables and write them to SSTables. Multiple workers enable parallel flushing across column families.

**Compaction workers** (configurable, default 2 threads) merge SSTables across levels. Multiple workers enable parallel compaction of different level ranges.

**Sync worker** (1 thread) periodically fsyncs write-ahead logs for column families configured with interval sync mode. It scans all column families, finds the minimum sync interval, sleeps for that duration, and fsyncs all WALs.

**Reaper worker** (1 thread) closes unused SSTable file handles when the open file count exceeds the limit (configurable, default 512). It sorts SSTables by last access time (updated atomically on each SSTable open, not on every read) and closes the oldest 25%. With more SSTables than the limit, the reaper runs continuously, causing file descriptor thrashing.

### Work Distribution

The database maintains two global work queues: one for flush operations, one for compaction operations. Each work item identifies the target column family. When a memtable exceeds its size threshold, the system enqueues a flush work item containing the column family pointer and immutable memtable. When a level exceeds capacity, it enqueues a compaction work item with the column family and level range.

Workers call `queue_dequeue_wait()` to block until work arrives. Multiple workers can process different column families simultaneously - worker 1 might flush column family A while worker 2 flushes column family B. Each column family uses atomic flags to prevent concurrent operations on the same structure: only one flush can run per column family at a time, and only one compaction per level range.

This design enables parallelism across column families while avoiding conflicts within a single column family. With N column families and 2 flush workers, flush latency is roughly N/2 × flush_time. The global queue provides natural load balancing - whichever worker finishes first picks up the next item, regardless of which column family it belongs to.

Workers coordinate through thread-safe queues and atomic flags. The main thread enqueues work and returns immediately. Workers process work asynchronously, allowing high write throughput.

## Error Handling

Functions return integer error codes. Zero indicates success; negative values indicate specific errors:

- `TDB_ERR_MEMORY` (-1): allocation failure
- `TDB_ERR_INVALID_ARGS` (-2): invalid parameters
- `TDB_ERR_NOT_FOUND` (-3): key not found
- `TDB_ERR_IO` (-4): I/O error
- `TDB_ERR_CORRUPTION` (-5): data corruption detected
- `TDB_ERR_CONFLICT` (-7): transaction conflict

The system distinguishes transient errors (disk space, memory) from permanent errors (corruption, invalid arguments). Critical operations use fsync for durability. All disk reads validate checksums.

**Error scenarios:**

- **Disk full during flush** · Flush fails, memtable remains in immutable queue. Writes continue to active memtable. When active memtable fills, writes stall (no more memtable swaps possible). System logs error but does not fail writes until memory exhausted.

- **Corruption during read** · Returns `TDB_ERR_CORRUPTION` to caller. Does not mark SSTable as bad - subsequent reads may succeed if corruption is localized to one block.

- **Corruption during compaction** · `tidesdb_merge_heap_pop()` detects corruption when advancing a source, returns the corrupted SSTable. Compaction marks it for deletion and continues with remaining sources.

- **Memory allocation failure during compaction** · Compaction aborts, returns `TDB_ERR_MEMORY`. Old SSTables remain intact. Compaction retries on next trigger.

- **Comparator changes between restarts** · Keys will be in wrong order within SSTables. Binary search will miss existing keys (returns NOT_FOUND for keys that exist). Iterators will return keys out of order. Compaction will produce incorrectly sorted output. The system does not detect comparator changes - this is a configuration error that corrupts the logical structure without corrupting the physical data.

- **Bloom filter false positives** · Cause 2 unnecessary disk reads (block index + block) but no errors.

## Design Rationale

### Block Size

Blocks balance compression efficiency and random access granularity. Larger blocks compress better (more context for LZ4/Zstd) but require reading more data for point lookups. Smaller blocks reduce read amplification but compress poorly and increase block index size. The fixed 64KB block size matches common SSD page sizes and provides reasonable compression ratios (typically 2-3× for text data). The tradeoff: a point lookup reads 64KB even for a 100-byte value.

### Level Size Ratio

Each level holds N× more data than the previous level. This determines write amplification. Lower ratios (5×) reduce write amp but increase levels (worse reads). Higher ratios (20×) reduce levels but increase write amp. The ratio is configurable per column family (default 10×).

**Write amplification** · In leveled compaction, each entry gets rewritten once per level it passes through. With ratio R and L levels, average write amplification is approximately R × L / 2 (not R × L) because data at shallow levels gets rewritten more than data at deep levels. For a 1TB database with default 64MB L1 and ratio 10: log₁₀(1TB/64MB) ≈ 7 levels, so ~35× average write amplification (not 70×). Actual write amp depends on workload - updates to existing keys have lower write amp than pure inserts.

**Read amplification** · Worst case reads one SSTable per level. With 7 levels, that's 7 disk reads without bloom filters. Bloom filters (1% FPR) reduce this: expected reads ≈ 1 + 7×0.01 = 1.07 for absent keys. This is an approximation valid for small FPR (probability of no false positives across all levels ≈ 0.99^7 ≈ 0.93). For present keys, bloom filters don't help - still need to read the actual block.

### Value Log Threshold

Values exceeding the configured threshold (default 4KB) go to the value log. This keeps the key log compact for efficient scanning. The threshold balances two costs: small thresholds cause many value log lookups (extra disk seeks); large thresholds bloat the key log (more data to scan during iteration). The default 4KB is a heuristic - it's roughly the size where the indirection cost (reading vlog offset, seeking to vlog, reading value) becomes cheaper than scanning a large inline value during iteration.

### Bloom Filter FPR

The default 1% false positive rate balances memory usage and effectiveness. Lower FPR (0.1%) requires 10× more bits per key but only reduces false positives by 10×. Higher FPR (5%) saves memory but causes more unnecessary disk reads. At 1% FPR, a bloom filter uses roughly 10 bits per key. For 1M keys, that's 1.25MB - small enough to keep in memory. The FPR is configurable per column family.

### Memtable Size

Larger memtables reduce flush frequency but increase recovery time and memory usage. Smaller memtables flush more often (more SSTables, more compaction) but recover faster. The default size is 64MB, which holds roughly 1M small key-value pairs and flushes every few seconds under moderate write load.

**Configuration interaction** · Increasing memtable size to 128MB reduces flush frequency by 2× but also increases L0→L1 write amplification because each flush produces a larger SSTable that takes longer to merge. The optimal size depends on write rate and acceptable recovery time.

### Worker Thread Counts

The default configuration uses 2 flush workers and 2 compaction workers to enable parallelism across column families while limiting resource usage. More threads help with multiple active column families but increase memory (each worker buffers 64KB blocks during merge) and file descriptor usage (2 FDs per SSTable being read/written). The counts are configurable.

**Tradeoff** · With N column families and 2 flush workers, flush latency is roughly N/2 × flush_time. Increasing to 4 workers halves latency but doubles memory usage during concurrent flushes.

**Disk contention** · On HDDs, multiple concurrent compaction workers cause head seeks, destroying throughput. On NVMe SSDs with high parallelism, multiple workers improve throughput. Choose worker counts based on storage device characteristics: 1-2 workers for HDD, 4-8 for NVMe.

## Operational Considerations

### Memory Footprint

Per column family:
- Active memtable · configurable (default 64MB)
- Immutable memtables · memtable_size × queue depth (typically 1-2)
- Block cache · shared across all column families (configurable, default 64MB total)
- Bloom filters · ~10 bits per key across all SSTables (depends on FPR)
- Block indexes · ~32 bytes per block across all SSTables

For a column family with 10M keys across 100 SSTables using defaults: ~12MB bloom filters, ~2MB block indexes, 128MB memtables. Total: ~150MB plus block cache share.

### Compaction Lag

Writes can outpace compaction if the write rate exceeds the compaction throughput. The system applies backpressure: when L0 exceeds 10 SSTables (configurable), writes stall until compaction catches up. This prevents unbounded memory growth but can cause write latency spikes.

### Disk Space

SSTables are immutable - space isn't reclaimed until compaction completes and old SSTables are deleted. Worst case: during compaction, both input and output SSTables exist simultaneously. For a level with 1GB of data, compaction temporarily requires 2GB. The system checks available disk space before starting compaction.

### File Descriptor Usage

Each SSTable uses 2 file descriptors (klog and vlog). With the default 512 open SSTable limit and 1000 total SSTables, the reaper constantly opens and closes files. This causes file descriptor thrashing. Increase the limit or reduce SSTable count through more aggressive compaction.

## Internal Components

TidesDB's internal components are designed as reusable, well-tested modules with clean interfaces. Each component solves a specific problem and integrates with the core LSM tree implementation through clearly defined APIs.

### Block Manager

The block manager provides a lock-free, append-only file abstraction with atomic reference counting and checksumming. Each file begins with an 8-byte header (3-byte magic "TDB", 1-byte version, 4-byte padding). Blocks consist of a header (4-byte size, 4-byte xxHash32 checksum), data, and footer (4-byte size duplicate, 4-byte magic "BTDB") for fast backward validation.

**Lock-free concurrency** · Writers use `pread`/`pwrite` for position-independent I/O, allowing concurrent reads and writes without locks. These POSIX functions are abstracted through `compat.h` for cross-platform support (Windows uses `ReadFile`/`WriteFile` with `OVERLAPPED` structures). The file size is tracked atomically in memory to avoid syscalls. Blocks use atomic reference counting - callers must call `block_manager_block_release()` when done, and blocks free when refcount reaches zero. Durability operations use `fdatasync` (also abstracted via `compat.h`).

**Cursor abstraction** · Block manager cursors enable sequential and random access. Cursors maintain current position and can move forward, backward, or jump to specific offsets. The `cursor_read_partial()` operation reads only the first N bytes of a block, useful for reading headers without loading large values.

**Validation modes** · The system supports strict (reject any corruption) and permissive (truncate to last valid block) validation. WAL files use permissive mode to handle crashes during writes. SSTable files use strict mode since they must be correct. Validation walks backward from the file end, checking footer magic numbers.

**Integration** · TidesDB uses block managers for all persistent storage - WAL files, klog files, and vlog files. The atomic offset allocation enables concurrent flush and compaction workers to write to different files simultaneously. The reference counting prevents use-after-free when multiple readers access the same SSTable.

### Bloom Filter

The bloom filter implementation uses a packed bitset (uint64_t words) with multiple hash functions to provide probabilistic set membership testing. The filter calculates optimal parameters from the desired false positive rate and expected element count: `m = -n*ln(p)/(ln(2)^2)` bits and `h = (m/n)*ln(2)` hash functions.

**Sparse serialization** · The filter serializes using varint encoding for headers and sparse encoding for the bitset - it stores only non-zero words with their indices. This achieves 70-90% space savings for low fill rates (< 50%). The serialization format: varint(m), varint(h), varint(non_zero_count), then pairs of varint(index) and uint64_t(word).

**Hash function** · Uses a simple multiplicative hash with different seeds for each of the h hash functions. Each hash sets one bit in the bitset using `bitset[hash % m / 64] |= (1ULL << (hash % 64))`.

**Integration** · TidesDB creates one bloom filter per SSTable during flush, adding all keys. The filter is serialized and written to the klog file after data blocks. During reads, the system checks the bloom filter before consulting the block index. With 1% FPR, this eliminates 99% of disk reads for absent keys. The filter is loaded into memory when an SSTable is opened and remains resident.

### Buffer

The buffer provides a lock-free slot allocator with atomic state machines and generation counters for ABA prevention. Each slot has four states: FREE (0), ACQUIRED (1), OCCUPIED (2), RELEASING (3). State transitions use atomic compare-and-swap operations.

**Lock-free acquire** · `buffer_acquire()` scans from a hint index (atomically incremented) to find a FREE slot, atomically transitions it to ACQUIRED, stores data, then transitions to OCCUPIED. If no slots are available, it retries with exponential backoff. The hint index reduces contention by spreading acquire attempts across the buffer.

**Generation counters** · Each slot maintains a generation counter incremented on release. This prevents ABA problems where a slot is released and reacquired between two operations. Callers can validate (slot_id, generation) pairs to ensure they're still referencing the same allocation.

**Eviction callbacks** · The buffer supports optional eviction callbacks invoked when slots are released. This enables custom cleanup logic without requiring callers to track allocations.

**Integration** · TidesDB uses buffers for tracking active transactions in each column family (`active_txn_buffer`, configurable, default 64K slots). During serializable isolation, the system needs to detect conflicts between concurrent transactions. The buffer stores transaction entries that can be quickly scanned for conflict detection. The eviction callback (`txn_entry_evict`) frees transaction metadata when slots are released. The lock-free design allows concurrent transaction begins without blocking.

### Clock Cache

The clock cache implements a partitioned, lock-free cache with hybrid hash table + CLOCK eviction. Each partition contains a circular array of slots for CLOCK and a separate hash index for O(1) lookups. The hash index uses linear probing with a maximum probe distance of 64.

**Partitioning** · The cache divides into N partitions (default: 2 per CPU core, up to 128). Each partition has independent CLOCK hand and hash index. Keys are hashed to partitions using `hash(key) & partition_mask`. This reduces contention - with 64 partitions and 16 threads, average contention is 16/64 = 0.25 threads per partition.

**Lock-free operations** · Entries use atomic state machines (EMPTY, WRITING, VALID, DELETING). Get operations are fully lock-free: hash to partition, probe hash index for slot, atomically load entry, set ref_bit, return pointer. Put operations claim a slot by advancing the CLOCK hand until finding an entry with ref_bit=0 and state=VALID, then atomically transition to WRITING.

**Zero-copy reads** · `clock_cache_get_zero_copy()` returns a pointer to cached data without copying. The CLOCK hand skips entries with ref_bit=1 (actively in use). Callers must call `clock_cache_release()` to clear the ref_bit when done.

**Integration** · TidesDB uses the clock cache for deserialized klog blocks. Cache keys are "cf_name:sstable_id:block_offset". On cache hit, the system increments the ref_bit and returns the cached block without disk I/O or deserialization. Multiple readers share the same cached block. The zero-copy design eliminates memory allocation on the hot read path.

### Skip List

The skip list provides a lock-free, multi-versioned ordered map with MVCC support. Each key has a linked list of versions, newest first. Versions store sequence numbers, values, TTL, and tombstone flags. The skip list uses probabilistic leveling (default p=0.25, max_level=32) for O(log n) average search time.

**Lock-free updates** · Insert operations use optimistic concurrency - traverse to find position, create new node, then atomically CAS the forward pointers. If CAS fails (concurrent modification), retry from the beginning. The implementation uses atomic operations for all pointer updates and supports up to 1000 CAS attempts before failing.

**Multi-version storage** · Each key maintains a version chain. New writes prepend a version to the chain using atomic CAS on the version list head. Readers traverse the version chain to find the appropriate version for their snapshot sequence. Tombstones are represented as versions with the DELETED flag set.

**Bidirectional traversal** · Nodes store both forward and backward pointers at each level. Forward pointers enable ascending iteration, backward pointers enable descending iteration. The backward pointers are stored in the same array as forward pointers: `forward[max_level+1+level]`.

**Custom comparators** · The skip list supports pluggable comparator functions with context pointers. TidesDB uses this for column families with different key orderings (memcmp, lexicographic, uint64, int64, custom).

**Integration** · TidesDB uses skip lists for memtables. The lock-free design allows concurrent reads and writes without blocking. The multi-version storage implements MVCC - readers see consistent snapshots while writers add new versions. During flush, the system creates an iterator and writes versions in sorted order to SSTables.

### Queue

The queue provides a thread-safe FIFO with node pooling and blocking dequeue. Operations use a mutex for writes and atomic operations for lock-free size queries. The queue maintains both a regular head pointer (protected by lock) and an atomic_head pointer for lock-free reads.

**Node pooling** · The queue maintains a free list of reusable nodes (up to 64). When dequeuing, nodes are returned to the pool instead of freed. When enqueuing, nodes are allocated from the pool if available. This reduces malloc/free overhead for high-throughput workloads.

**Blocking dequeue** · `queue_dequeue_wait()` blocks on a condition variable until the queue becomes non-empty or shutdown. This enables worker threads to sleep when idle instead of spinning. The shutdown flag allows graceful termination - workers wake up and exit when the queue is destroyed.

**Lock-free size** · The size is stored atomically, allowing readers to query `queue_size()` without acquiring the lock. This is used by the flush drain logic to check if work remains without blocking.

**Integration** · TidesDB uses queues for work distribution to background workers. The flush queue holds immutable memtables awaiting flush. The compaction queue holds compaction work items. Workers call `queue_dequeue_wait()` to block until work arrives. The node pooling reduces allocation overhead when memtables flush frequently.

### Manifest

The manifest tracks SSTable metadata in a simple text format with reader-writer locks for concurrency. Each line represents one SSTable: `level,id,num_entries,size_bytes`. The manifest file begins with a version header and global sequence number.

**In-memory representation** · The manifest maintains an array of entries with dynamic resizing (starts at 64, doubles when full). Entries are unsorted - lookups are O(n). This is acceptable because manifest operations are infrequent (only during flush/compaction) and the number of SSTables per column family is typically < 1000.

**Atomic commits** · The manifest file is kept open for efficient commits. `tidesdb_manifest_commit()` seeks to the beginning, writes all entries, truncates to the new size, and fsyncs. This ensures the manifest is always consistent - either the old version or the new version is visible, never a partial update.

**Concurrency control** · Reader-writer locks allow multiple concurrent readers (checking if an SSTable exists) but exclusive writers (adding/removing SSTables). The `active_ops` counter tracks ongoing operations - `tidesdb_manifest_close()` waits for active_ops to reach zero before closing.

**Integration** · TidesDB uses one manifest per column family. During flush, the system adds the new SSTable to the manifest and fsyncs before deleting the WAL. During compaction, it adds new SSTables and removes old ones atomically. During recovery, it reads the manifest to determine which SSTables belong to which levels. The manifest is the source of truth for the LSM tree structure.

### Platform Compatibility (compat.h)

The `compat.h` header isolates all platform-specific code, enabling TidesDB to run on Windows (MSVC, MinGW), macOS, Linux, BSD variants, and Solaris/Illumos without changes to the core implementation. I/O operations (`pread`/`pwrite`, `fdatasync`) map to Windows equivalents (`ReadFile`/`WriteFile` with `OVERLAPPED`, `FlushFileBuffers`). Atomics use C11 `stdatomic.h` on modern compilers or Windows `Interlocked*` functions on older MSVC. Threading uses POSIX `pthread` (pthreads-win32 on MSVC, native on MinGW). File system operations (`opendir`/`readdir`) map to Windows `FindFirstFile`/`FindNextFile`. Semaphores use Windows APIs on MSVC, native `semaphore.h` elsewhere. Type definitions handle platform differences (`off_t`, `ssize_t`, format specifiers). Performance hints (`PREFETCH_READ`, `LIKELY`, `UNLIKELY`) use compiler intrinsics where available. Every source file includes `compat.h` first. The abstraction layer has zero runtime overhead - all macros and inline functions compile to native platform calls.

## Testing and Quality Assurance

TidesDB employs comprehensive testing with CI/CD automation across 10+ platform/architecture combinations. Each internal component has dedicated test files (`block_manager__tests.c`, `skip_list__tests.c`, `bloom_filter__tests.c`, etc.) with unit tests, integration tests, and performance benchmarks. The main integration suite (`tidesdb__tests.c`) contains 100+ tests covering the full database lifecycle: basic operations, transactions across all isolation levels, persistence, WAL recovery, compaction strategies, iterators, TTL, compression, bloom filters, block indexes, concurrent operations, edge cases, and stress tests. Test utilities (`test_utils.h`) provide assertion macros and execution harnesses with colored output.

The CMake build system automatically configures for Linux (x64, x86, PowerPC), macOS (x64, x86, Intel, Apple Silicon), Windows (MSVC x64/x86, MinGW x64/x86), BSD variants, and Solaris/Illumos. It manages dependencies via vcpkg (Windows with binary caching), Homebrew (macOS), and pkg-config (Linux), handles cross-compilation for PowerPC with custom-built dependencies, enables sanitizers (AddressSanitizer, UndefinedBehaviorSanitizer) on Unix platforms, provides 30+ benchmark configuration variables, and registers tests with CTest for execution.

GitHub Actions CI builds and tests all 10 platform/architecture combinations, installs compression libraries (zstd, lz4, snappy) and pthreads on each platform, cross-compiles PowerPC builds with dependencies built from source, and runs tests via CTest (native platforms) or QEMU emulation (PowerPC). A cross-platform portability test creates a database on Linux x64, uploads it as an artifact, downloads it on 7 different platforms, and verifies all keys are readable with correct values - proving the database format is truly portable across architectures and endianness. Windows builds use vcpkg binary caching to reduce build times from 20+ minutes to 2-3 minutes on cache hits.

The testing infrastructure ensures TidesDB maintains correctness, performance, and portability across all supported platforms.