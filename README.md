<div>
    <h1 align="left"><img width="128" src="artwork/tidesdb-logo-v0.1.png"></h1>
</div>

TidesDB is a fast and efficient key value storage engine library written in C.
The underlying data structure is based on a log-structured merge-tree (LSM-tree).

It is not a full-featured database, but rather a library that can be used to build a database atop of or used as a standalone key-value/column store.

[![Linux Build Status](https://github.com/tidesdb/tidesdb/actions/workflows/build_and_test_tidesdb.yml/badge.svg)](https://github.com/tidesdb/tidesdb/actions/workflows/build_and_test_tidesdb.yml)

## Features
- [x] **ACID Transactions** - Atomic, consistent, isolated, and durable. Transactions support multiple operations across column families.
- [x] **Optimized Concurrency** - Writers don't block readers. Readers never block other readers. Flush and compaction I/O happens outside locks with only brief blocking for metadata updates. Atomic memtable operations.
- [x] **Column Families** - Isolated key-value stores. Each column family has its own memtable, SSTables, and WAL.
- [x] **Atomic Transactions** - Commit or rollback multiple operations atomically. Failed transactions automatically rollback.
- [x] **Bidirectional Iterators** - Iterate forward and backward over key-value pairs with merge-sort across memtable and SSTables.
- [x] **Write-Ahead Log (WAL)** - Durability through WAL. Automatic recovery on startup reconstructs memtables from WALs.
- [x] **Background Compaction** - Automatic background compaction when SSTable count reaches configured max per column family.
- [x] **Bloom Filters** - Reduce disk reads by checking key existence before reading SSTables. Configurable false positive rate.
- [x] **Compression** - Snappy, LZ4, or ZSTD compression for SSTables and WAL entries. Configurable per column family.
- [x] **TTL Support** - Time-to-live for key-value pairs. Expired entries automatically skipped during reads.
- [x] **Custom Comparators** - Register custom key comparison functions. Built-in comparators `memcmp, string, numeric`.
- [x] **Sync Modes** - Three sync modes `NONE (fastest), BACKGROUND (balanced), FULL (most durable)`.
- [x] **Configurable** - Per-column-family configuration `memtable size, compaction settings, compression, bloom filters, sync mode`.
- [x] **Simple API** - Clean, easy-to-use C API. Returns 0 on success, -n on error.
- [x] **Skip List Memtable** - COW and atomic skip list for in-memory storage with configurable max level and probability.
- [x] **Cross-Platform** - Linux, macOS, and Windows support with platform abstraction layer.
- [x] **Sorted Binary Hash Array (SBHA)** - Fast SSTable lookups. Direct key-to-block offset mapping without full SSTable scans.
- [x] **Tombstones** - Efficient deletion through tombstone markers. Removed during compaction.
- [x] **LRU File Handle Cache** - Configurable LRU cache for open file handles. Limits system resources while maintaining performance. Set `max_open_file_handles` to control cache size (0 = disabled).

## Building
Using cmake to build the shared library.

### Unix (Linux/macOS)
```bash
rm -rf build && cmake -S . -B build
cmake --build build
cmake --install build

# Production build
rm -rf build && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DTIDESDB_WITH_SANITIZER=OFF -DTIDESDB_BUILD_TESTS=OFF
cmake --build build --config Release
sudo cmake --install build

# On linux run ldconfig to update the shared library cache
ldconfig
```

### Windows

#### Option 1 MinGW-w64 (Recommended for Windows)
MinGW-w64 provides a GCC-based toolchain with better C11 support and POSIX compatibility.

**Prerequisites**
- Install [MinGW-w64](https://www.mingw-w64.org/)
- Install [CMake](https://cmake.org/download/)
- Install [vcpkg](https://vcpkg.io/en/getting-started.html) for dependencies

**Build Steps**
```powershell
# Clean previous build
Remove-Item -Recurse -Force build -ErrorAction SilentlyContinue

# Configure with MinGW
cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_C_COMPILER=gcc -DCMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake

# Build
cmake --build build

# Run tests
cd build
ctest --verbose  # or use --output-on-failure to only show failures
```

#### Option 2 MSVC (Visual Studio)
**Prerequisites**
- Install [Visual Studio 2019 or later](https://visualstudio.microsoft.com/) with C++ development tools
- Install [CMake](https://cmake.org/download/)
- Install [vcpkg](https://vcpkg.io/en/getting-started.html) for dependencies

**Build Steps**
```powershell
# Clean previous build
Remove-Item -Recurse -Force build -ErrorAction SilentlyContinue

# Configure with MSVC
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake

# Build (Debug or Release)
cmake --build build --config Debug
# or
cmake --build build --config Release

# Run tests
cd build
ctest -C Debug --verbose
# or
ctest -C Release --verbose

```

**Note** MSVC requires Visual Studio 2019 16.8 or later for C11 atomics support (`/experimental:c11atomics`). Both Debug and Release builds are fully supported.

## Requirements
You need cmake and a C compiler.
You also require the `snappy`, `lz4`, `zstd`, and `openssl` libraries.

### Dependencies
- [Snappy](https://github.com/google/snappy) - Compression
- [LZ4](https://github.com/lz4/lz4) - Compression
- [Zstandard](https://github.com/facebook/zstd) - Compression
- [OpenSSL](https://www.openssl.org/) - Cryptographic hashing (SHA1)

### Linux
```bash
sudo apt install libzstd-dev
sudo apt install liblz4-dev
sudo apt install libsnappy-dev
sudo apt install libssl-dev
```

### MacOS
```bash
brew install zstd
brew install lz4
brew install snappy
brew install openssl
```

### Windows
Windows using vcpkg
```bash
vcpkg install zstd
vcpkg install lz4
vcpkg install snappy
vcpkg install openssl
```

## Discord Community
Join the [TidesDB Discord Community](https://discord.gg/tWEmjR66cy) to ask questions, work on development, and discuss the future of TidesDB.

## Include
```c
#include <tidesdb/tidesdb.h> /* You can use other components of TidesDB such as skip list, bloom filter etc.. under tidesdb/
                                this also prevents collisions. */
```

## Error Codes
TidesDB provides detailed error codes for production use. All functions return `0` on success or a negative error code on failure.

| Error Code | Value | Description |
|------------|-------|-------------|
| `TDB_SUCCESS` | 0 | operation successful |
| `TDB_ERROR` | -1 | generic error |
| `TDB_ERR_MEMORY` | -2 | memory allocation failed |
| `TDB_ERR_INVALID_ARGS` | -3 | invalid arguments passed to function |
| `TDB_ERR_IO` | -4 | I/O error (file operations) |
| `TDB_ERR_NOT_FOUND` | -5 | key not found |
| `TDB_ERR_EXISTS` | -6 | resource already exists |
| `TDB_ERR_CORRUPT` | -7 | data corruption detected |
| `TDB_ERR_LOCK` | -8 | lock acquisition failed |
| `TDB_ERR_TXN_COMMITTED` | -9 | transaction already committed |
| `TDB_ERR_TXN_ABORTED` | -10 | transaction aborted |
| `TDB_ERR_READONLY` | -11 | write operation on read-only transaction |
| `TDB_ERR_FULL` | -12 | database or resource full |
| `TDB_ERR_INVALID_NAME` | -13 | invalid name (too long or empty) |
| `TDB_ERR_COMPARATOR_NOT_FOUND` | -14 | comparator not found in registry |
| `TDB_ERR_MAX_COMPARATORS` | -15 | maximum number of comparators reached |
| `TDB_ERR_INVALID_CF` | -16 | invalid column family |
| `TDB_ERR_THREAD` | -17 | thread creation or operation failed |
| `TDB_ERR_CHECKSUM` | -18 | checksum verification failed |

**Example error handling**
```c
int result = tidesdb_txn_put(txn, "my_cf", key, key_size, value, value_size, -1);
if (result != TDB_SUCCESS)
{
    switch (result)
    {
        case TDB_ERR_MEMORY:
            fprintf(stderr, "out of memory\n");
            break;
        case TDB_ERR_INVALID_ARGS:
            fprintf(stderr, "invalid arguments\n");
            break;
        case TDB_ERR_READONLY:
            fprintf(stderr, "cannot write to read-only transaction\n");
            break;
        default:
            fprintf(stderr, "operation failed with error code: %d\n", result);
            break;
    }
    return -1;
}
```

## Usage
TidesDB v1 uses a simplified API. All functions return `0` on success and a negative error code on failure.

### Opening a database
To open a database you pass a config struct and a pointer to the database.
```c
tidesdb_config_t config = {
    .db_path = "./mydb",
    .enable_debug_logging = 0  /* Optional enable debug logging */
};

tidesdb_t *db = NULL;
if (tidesdb_open(&config, &db) != 0)
{
    /* Handle error */
    return -1;
}

/* Close the database */
if (tidesdb_close(db) != 0)
{
    /* Handle error */
    return -1;
}
```

### Debug Logging
TidesDB provides runtime debug logging that can be enabled/disabled dynamically.

**Enable at startup**
```c
tidesdb_config_t config = {
    .db_path = "./mydb",
    .enable_debug_logging = 1  /* Enable debug logging */
};

tidesdb_t *db = NULL;
tidesdb_open(&config, &db);
```

**Enable/disable at runtime**
```c
extern int _tidesdb_debug_enabled;  /* Global debug flag */

/* Enable debug logging */
_tidesdb_debug_enabled = 1;

/* Your operations here - debug logs will be written to stderr */

/* Disable debug logging */
_tidesdb_debug_enabled = 0;
```

**Output**
Debug logs are written to **stderr** with the format
```
[TidesDB DEBUG] filename:line: message
```

**Redirect to file**
```bash
./your_program 2> tidesdb_debug.log  # Redirect stderr to file
```

### Creating a column family
Column families are isolated key-value stores. Use the config struct for customization or use defaults.

```c
/* Create with default configuration */
tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

if (tidesdb_create_column_family(db, "my_cf", &cf_config) != 0)
{
    /* Handle error */
    return -1;
}
```

**Custom configuration example**
```c
tidesdb_column_family_config_t cf_config = {
    .memtable_flush_size = 128 * 1024 * 1024,   /* 128MB */
    .max_sstables_before_compaction = 512,      /* trigger compaction at 512 SSTables (min 2 required) */
    .compaction_threads = 4,                    /* use 4 threads for parallel compaction (0 = single-threaded) */
    .max_level = 12,                            /* skip list max level */
    .probability = 0.25f,                       /* skip list probability */
    .compressed = 1,                            /* enable compression */
    .compress_algo = COMPRESS_LZ4,              /* use LZ4 */
    .bloom_filter_fp_rate = 0.01,               /* 1% false positive rate */
    .enable_background_compaction = 1,          /* enable background compaction */
    .background_compaction_interval = 1000000,  /* check every 1000000 microseconds (1 second) */
    .use_sbha = 1,                              /* use sorted binary hash array */
    .sync_mode = TDB_SYNC_BACKGROUND,           /* background fsync */
    .sync_interval = 1000,                      /* fsync every 1000ms (1 second) */
    .comparator_name = NULL                     /* NULL = use default "memcmp" */
};

if (tidesdb_create_column_family(db, "my_cf", &cf_config) != 0)
{
    /* Handle error */
    return -1;
}
```

**Using custom comparator**
```c
/* Register custom comparator first (see examples/custom_comparator.c) */
tidesdb_register_comparator("reverse", my_reverse_compare);

tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
cf_config.comparator_name = "reverse";  /* use registered comparator */

if (tidesdb_create_column_family(db, "sorted_cf", &cf_config) != 0)
{
    /* Handle error */
    return -1;
}
```


### Dropping a column family

```c
if (tidesdb_drop_column_family(db, "my_cf") != 0)
{
    /* Handle error */
    return -1;
}
```

### Getting a column family
Retrieve a column family pointer to use in operations.
```c
tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "my_cf");
if (cf == NULL)
{
    /* Column family not found */
    return -1;
}
```

### Listing column families
Get all column family names in the database.
```c
char **names = NULL;
int count = 0;

if (tidesdb_list_column_families(db, &names, &count) == 0)
{
    printf("Found %d column families:\n", count);
    for (int i = 0; i < count; i++)
    {
        printf("  - %s\n", names[i]);
        free(names[i]);  /* Free each name */
    }
    free(names);  /* Free the array */
}
```

### Column family statistics
Get detailed statistics about a column family.
```c
tidesdb_column_family_stat_t *stats = NULL;

if (tidesdb_get_column_family_stats(db, "my_cf", &stats) == 0)
{
    printf("Column Family: %s\n", stats->name);
    printf("Comparator: %s\n", stats->comparator_name);
    printf("SSTables: %d\n", stats->num_sstables);
    printf("Total SSTable Size: %zu bytes\n", stats->total_sstable_size);
    printf("Memtable Size: %zu bytes\n", stats->memtable_size);
    printf("Memtable Entries: %d\n", stats->memtable_entries);
    printf("Compression: %s\n", stats->config.compressed ? "enabled" : "disabled");
    printf("Bloom Filter FP Rate: %.4f\n", stats->config.bloom_filter_fp_rate);
    
    free(stats);
}
```

**Statistics include**
- Column family name and comparator
- Number of SSTables and total size
- Memtable size and entry count
- Full configuration (compression, bloom filters, sync mode, etc.)

### Transactions
All operations in TidesDB v1 are done through transactions for ACID guarantees.

**Basic transaction**
```c
tidesdb_txn_t *txn = NULL;
if (tidesdb_txn_begin(db, &txn) != 0)
{
    return -1;
}

/* Put a key-value pair */
const uint8_t *key = (uint8_t *)"mykey";
const uint8_t *value = (uint8_t *)"myvalue";

if (tidesdb_txn_put(txn, "my_cf", key, 5, value, 7, -1) != 0)
{
    tidesdb_txn_free(txn);
    return -1;
}

/* Commit the transaction */
if (tidesdb_txn_commit(txn) != 0)
{
    tidesdb_txn_free(txn);
    return -1;
}

tidesdb_txn_free(txn);
```

**With TTL (time-to-live)**
```c
tidesdb_txn_t *txn = NULL;
tidesdb_txn_begin(db, &txn);

const uint8_t *key = (uint8_t *)"temp_key";
const uint8_t *value = (uint8_t *)"temp_value";

/* TTL is Unix timestamp (seconds since epoch) - absolute expiration time */
time_t ttl = time(NULL) + 60;  /* Expires 60 seconds from now */

/* Use -1 for no expiration */
tidesdb_txn_put(txn, "my_cf", key, 8, value, 10, ttl);
tidesdb_txn_commit(txn);
tidesdb_txn_free(txn);
```

**TTL Examples**
```c
/* No expiration */
time_t ttl = -1;

/* Expire in 5 minutes */
time_t ttl = time(NULL) + (5 * 60);

/* Expire in 1 hour */
time_t ttl = time(NULL) + (60 * 60);

/* Expire at specific time (e.g., midnight) */
time_t ttl = 1730592000;  /* Specific Unix timestamp */
```

**Getting a key-value pair**
```c
tidesdb_txn_t *txn = NULL;
tidesdb_txn_begin_read(db, &txn);  /* Read-only transaction */

const uint8_t *key = (uint8_t *)"mykey";
uint8_t *value = NULL;
size_t value_size = 0;

if (tidesdb_txn_get(txn, "my_cf", key, 5, &value, &value_size) == 0)
{
    /* Use value */
    printf("Value: %.*s\n", (int)value_size, value);
    free(value);
}

tidesdb_txn_free(txn);
```

**Deleting a key-value pair**
```c
tidesdb_txn_t *txn = NULL;
tidesdb_txn_begin(db, &txn);

const uint8_t *key = (uint8_t *)"mykey";
tidesdb_txn_delete(txn, "my_cf", key, 5);

tidesdb_txn_commit(txn);
tidesdb_txn_free(txn);
```

**Multi-operation transaction**
```c
tidesdb_txn_t *txn = NULL;
tidesdb_txn_begin(db, &txn);

/* Multiple operations in one transaction */
tidesdb_txn_put(txn, "my_cf", (uint8_t *)"key1", 4, (uint8_t *)"value1", 6, -1);
tidesdb_txn_put(txn, "my_cf", (uint8_t *)"key2", 4, (uint8_t *)"value2", 6, -1);
tidesdb_txn_delete(txn, "my_cf", (uint8_t *)"old_key", 7);

/* Commit atomically - all or nothing */
if (tidesdb_txn_commit(txn) != 0)
{
    /* On error, transaction is automatically rolled back */
    tidesdb_txn_free(txn);
    return -1;
}

tidesdb_txn_free(txn);
```

**Transaction rollback**
```c
tidesdb_txn_t *txn = NULL;
tidesdb_txn_begin(db, &txn);

tidesdb_txn_put(txn, "my_cf", (uint8_t *)"key", 3, (uint8_t *)"value", 5, -1);

/* Decide to rollback instead of commit */
tidesdb_txn_rollback(txn);
tidesdb_txn_free(txn);
/* No changes were applied */
```

### Iterators
Iterators provide efficient forward and backward traversal over key-value pairs.

**Forward iteration**
```c
tidesdb_txn_t *txn = NULL;
tidesdb_txn_begin_read(db, &txn);

tidesdb_iter_t *iter = NULL;
if (tidesdb_iter_new(txn, "my_cf", &iter) != 0)
{
    tidesdb_txn_free(txn);
    return -1;
}

/* Seek to first entry */
tidesdb_iter_seek_to_first(iter);

while (tidesdb_iter_valid(iter))
{
    uint8_t *key = NULL;
    size_t key_size = 0;
    uint8_t *value = NULL;
    size_t value_size = 0;
    
    if (tidesdb_iter_key(iter, &key, &key_size) == 0 &&
        tidesdb_iter_value(iter, &value, &value_size) == 0)
    {
        /* Use key and value */
        printf("Key: %.*s, Value: %.*s\n", 
               (int)key_size, key, (int)value_size, value);
        free(key);
        free(value);
    }
    
    tidesdb_iter_next(iter);
}

tidesdb_iter_free(iter);
tidesdb_txn_free(txn);
```

**Backward iteration**
```c
tidesdb_txn_t *txn = NULL;
tidesdb_txn_begin_read(db, &txn);

tidesdb_iter_t *iter = NULL;
tidesdb_iter_new(txn, "my_cf", &iter);

/* Seek to last entry */
tidesdb_iter_seek_to_last(iter);

while (tidesdb_iter_valid(iter))
{
    /* Process entries in reverse order */
    tidesdb_iter_prev(iter);
}

tidesdb_iter_free(iter);
tidesdb_txn_free(txn);
```

**Iterator Compaction Resilience**

TidesDB iterators automatically handle compaction that occurs during iteration

- **Automatic Snapshot Refresh** - When an iterator detects that compaction has occurred (SSTable count changed), it automatically refreshes its internal snapshot with the new compacted SSTables
- **Seamless Continuation** - The iterator continues traversing data from the new SSTables without requiring manual intervention
- **No Blocking** - Compaction doesn't wait for iterators, and iterators don't block compaction
- **Read Lock Protection** - Each iteration operation holds a read lock, preventing SSTables from being freed during access

Do note that background compactions may cause duplicates in your results if keys were merged. You may need to handle duplicates in your application logic.

```c
tidesdb_iter_t *iter = NULL;
tidesdb_iter_new(txn, "my_cf", &iter);
tidesdb_iter_seek_to_first(iter);

while (tidesdb_iter_valid(iter))
{
    /* If compaction occurs here, iterator automatically refreshes */
    /* and continues reading from the new compacted SSTables */
    
    uint8_t *key = NULL, *value = NULL;
    size_t key_size = 0, value_size = 0;
    
    tidesdb_iter_key(iter, &key, &key_size);
    tidesdb_iter_value(iter, &value, &value_size);
    
    /* Process data */
    
    free(key);
    free(value);
    tidesdb_iter_next(iter);  /* Detects and handles compaction if it occurred */
}

tidesdb_iter_free(iter);
```

This design ensures iterators remain valid and functional even during active compaction, providing a robust and concurrent iteration experience.

### Custom Comparators
Register custom key comparison functions for specialized sorting.

**Register a comparator**
```c
/* Define your comparison function */
int my_reverse_compare(const uint8_t *key1, size_t key1_size,
                       const uint8_t *key2, size_t key2_size, void *ctx)
{
    int result = memcmp(key1, key2, key1_size < key2_size ? key1_size : key2_size);
    return -result;  /* reverse order */
}

/* Register it before creating column families */
tidesdb_register_comparator("reverse", my_reverse_compare);

/* Use in column family */
tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
cf_config.comparator_name = "reverse";
tidesdb_create_column_family(db, "sorted_cf", &cf_config);
```

**Built-in comparators**
- `"memcmp"` - Binary comparison (default)
- `"string"` - Lexicographic string comparison
- `"numeric"` - Numeric comparison for uint64_t keys

See `examples/custom_comparator.c` for more examples.

### Sync Modes
Control durability vs performance tradeoff.

```c
tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

/* TDB_SYNC_NONE - Fastest, least durable (OS handles flushing) */
cf_config.sync_mode = TDB_SYNC_NONE;

/* TDB_SYNC_BACKGROUND - Balanced (fsync every N milliseconds in background) */
cf_config.sync_mode = TDB_SYNC_BACKGROUND;
cf_config.sync_interval = 1000;  /* fsync every 1000ms (1 second) */

/* TDB_SYNC_FULL - Most durable (fsync on every write) */
cf_config.sync_mode = TDB_SYNC_FULL;

tidesdb_create_column_family(db, "my_cf", &cf_config);
```

## Background Compaction
TidesDB v1 features automatic background compaction with optional parallel execution.

**Automatic background compaction** runs when SSTable count reaches the configured threshold

```c
tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
cf_config.enable_background_compaction = 1;          /* Enable background compaction */
cf_config.background_compaction_interval = TDB_DEFAULT_BACKGROUND_COMPACTION_INTERVAL;  /* Check every 1000000 microseconds (1 second) */
cf_config.max_sstables_before_compaction = TDB_DEFAULT_MAX_SSTABLES;      /* Trigger at 128 SSTables (default) */
cf_config.compaction_threads = TDB_DEFAULT_COMPACTION_THREADS;                    /* Use 4 threads for parallel compaction */

tidesdb_create_column_family(db, "my_cf", &cf_config);
/* Background thread automatically compacts when threshold is reached */
```

**Configuration Options**
- `enable_background_compaction` - Enable/disable automatic background compaction (default: enabled)
- `background_compaction_interval` - Interval in microseconds between compaction checks (default: 1000000 = 1 second)
- `max_sstables_before_compaction` - SSTable count threshold to trigger compaction (default: 512, minimum: 2)
- `compaction_threads` - Number of threads for parallel compaction (default: 4, set to 0 for single-threaded)

**Parallel Compaction**
- Set `compaction_threads > 0` to enable parallel compaction
- Uses semaphore-based thread pool for concurrent SSTable pair merging
- Each thread compacts one pair of SSTables independently
- Automatically limits threads to available CPU cores
- Set `compaction_threads = 0` for single-threaded compaction (default 4 threads)

**Manual compaction** can be triggered at any time (requires minimum 2 SSTables)

```c
tidesdb_compact(cf);  /* Automatically uses parallel compaction if compaction_threads > 0 */
```

**Benefits**
- Removes tombstones and expired TTL entries
- Merges duplicate keys (keeps latest version)
- Reduces SSTable count
- Background compaction runs in separate thread (non-blocking)
- Parallel compaction significantly speeds up large compactions
- Manual compaction requires minimum 2 SSTables to merge

## Concurrency Model

TidesDB is designed for high concurrency with minimal blocking

**Reader-Writer Locks**
- Each column family has a reader-writer lock
- **Multiple readers can read concurrently** - no blocking between readers
- **Writers don't block readers** - readers can access data while writes are in progress
- **Writers block other writers** - only one writer per column family at a time

**Transaction Isolation**
- Read transactions (`tidesdb_txn_begin_read`) acquire read locks
- Write transactions (`tidesdb_txn_begin`) acquire write locks on commit
- Transactions are isolated - changes not visible until commit

**Optimal for**
- Read-heavy workloads (unlimited concurrent readers)
- Mixed read/write workloads (readers never wait for writers)
- Multi-column-family applications (different CFs can be written concurrently)

**Example - Concurrent Operations**
```c
/* Thread 1 Reading */
tidesdb_txn_t *read_txn;
tidesdb_txn_begin_read(db, &read_txn);
tidesdb_txn_get(read_txn, "my_cf", key, key_size, &value, &value_size);
/* Can read while Thread 2 is writing */

/* Thread 2 Writing */
tidesdb_txn_t *write_txn;
tidesdb_txn_begin(db, &write_txn);
tidesdb_txn_put(write_txn, "my_cf", key, key_size, value, value_size, -1);
tidesdb_txn_commit(write_txn);  /* Briefly blocks other writers only */

/* Thread 3 Reading different CF */
tidesdb_txn_t *other_txn;
tidesdb_txn_begin_read(db, &other_txn);
tidesdb_txn_get(other_txn, "other_cf", key, key_size, &value, &value_size);
/* No blocking different column family */
```

## License
Multiple

```
Mozilla Public License Version 2.0 (TidesDB)

-- AND --
BSD 3 Clause (Snappy)
BSD 2 (LZ4)
BSD 2 (xxHash - Yann Collet)
BSD (Zstandard)
Apache 2.0 (OpenSSL 3.0+) / OpenSSL License (OpenSSL 1.x)
```
