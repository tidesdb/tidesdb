---
title: Column Family Operations
description: Creating, dropping, renaming, cloning, and reconfiguring column families.
slug: reference/column-family
part: reference
sidebar:
  order: 2
---

# Column Family Operations

A column family is an independent keyspace inside one database. Each has its own levels,
its own sstables, and its own compaction policy, so families with different access patterns
do not interfere with each other's read amplification. They share the database's write-ahead
log, memtable, value log, and block cache, which is what makes a transaction spanning
several families atomic.

Keys are namespaced by family, so the same key may appear in several families with
different values. Ordering is byte-wise (`memcmp`) in every family; a caller who wants a
different order encodes keys to be memcomparable.

Handles returned by [`tidesdb_get_column_family`](#tidesdb_get_column_family) are **borrowed**.
They are owned by the database, live until the family is dropped or the database is closed,
and must never be freed.

## tidesdb_default_column_family_config

Return a column family configuration filled with defaults.

### Synopsis

```c
tidesdb_column_family_config_t tidesdb_default_column_family_config(void);
```

### Description

Returns the configuration by value; there is nothing to free. The `name` field is left
empty, and it does not matter what you put there — every call that takes a config also
takes the name separately, and the separate argument wins. See
[`tidesdb_create_column_family`](#tidesdb_create_column_family).

### Return Value

| Field | Default | Meaning |
| --- | --- | --- |
| `name` | empty | Ignored; the `name` argument is authoritative |
| `level_size_ratio` | 10 | Each level holds this many times the one above it |
| `min_levels` | 1 | Floor on the level count. A family already this deep is never shed further, however little its largest level holds |
| `dividing_level_offset` | 1 | How far above the largest level the dividing level sits, so 1 means `X = L - 2`. Lower rewrites more data per dividing merge; higher opens more files at once |
| `keep_values_inline` | 0 | Hold every value in the key log whatever its size, ignoring the database's `value_separation_threshold` |
| `btree_klog_block_size` | 4096 | Target btree node size in the key log |
| `encoding_pipeline` | empty | Encodings applied in order to btree klog nodes and separated values — see [Configuration](/appendix/configuration#what-the-encoding-pipeline-currently-does) |
| `encoding_count` | 0 | Entries in the pipeline |
| `enable_bloom_filter` | 1 | Build a partition range filter per sstable |
| `bloom_fpr` | 0.01 | Target false positive rate |
| `default_isolation_level` | `TDB_ISOLATION_READ_COMMITTED` | Level used by `tidesdb_txn_begin_cf` |
| `l1_file_count_trigger` | 4 | L1 file count that triggers compaction |
| `tombstone_density_trigger` | 0.5 | Tombstone fraction that triggers compaction |
| `tombstone_density_min_entries` | 4096 | Entry count below which the density trigger is ignored |
| `commit_hook_fn` | `NULL` | Optional commit hook, registered at create time |
| `commit_hook_ctx` | `NULL` | Context passed to the hook |

### Notes

Which values get separated is a database setting, `value_separation_threshold`, not a family
one. The value log is a single shared structure and the decision keys on the size of a value
rather than on which family holds it, so one cut-off serves a family of small metadata and a
family of large blobs alike. See [Configuration](/appendix/configuration).

`keep_values_inline` is the family-level exception. Values above the threshold are normally
written to the shared value log with the key log holding a reference, which keeps the btree
small and makes scans over keys fast, but a point read of a separated value costs a second
I/O and a range scan pays it per row. A family that is scanned far more often than it is
merged can set this and keep its values whole whatever their size. The cost is the one the
threshold exists to avoid, that compaction rewrites those bytes on every merge.

### See Also

[`tidesdb_create_column_family`](#tidesdb_create_column_family),
[`tidesdb_cf_update_runtime_config`](#tidesdb_cf_update_runtime_config)

## tidesdb_compression_available

Report whether this build can use a compression algorithm.

### Synopsis

```c
int tidesdb_compression_available(tidesdb_compression_algorithm_t type);
```

### Description

Every `tidesdb_compression_algorithm_t` enumerator is defined in every build, because the numeric
values are written into sstable and value-log metadata and a file written elsewhere has to stay
readable. Whether a given backend is actually linked in is a build-time choice — the
`-DTIDESDB_WITH_SNAPPY`, `-DTIDESDB_WITH_LZ4` and `-DTIDESDB_WITH_ZSTD` options — so the enum
being complete says nothing about what this binary can do.

| Algorithm | Value | Requires | Notes |
| --- | --- | --- | --- |
| `TDB_COMPRESS_NONE` | `0` | — | Always available; stores the data verbatim |
| `TDB_COMPRESS_SNAPPY` | `1` | `TIDESDB_WITH_SNAPPY` | |
| `TDB_COMPRESS_LZ4` | `2` | `TIDESDB_WITH_LZ4` | |
| `TDB_COMPRESS_ZSTD` | `3` | `TIDESDB_WITH_ZSTD` | Strongest ratio of the four backends |
| `TDB_COMPRESS_LZ4_FAST` | `4` | `TIDESDB_WITH_LZ4` | The LZ4 backend at a higher acceleration — faster, weaker ratio |

The values are the on-disk contract, written into sstable and value-log metadata, so they are fixed
and never reused. `TDB_COMPRESS_LZ4_FAST` is the same backend as `TDB_COMPRESS_LZ4` and differs
only in its acceleration setting, so the two are available together or not at all.

This is how a caller finds out. It matters because
[`tidesdb_create_column_family`](#tidesdb_create_column_family) and
[`tidesdb_cf_update_runtime_config`](#tidesdb_cf_update_runtime_config) both **reject** an
`encoding_pipeline` naming an algorithm this build lacks, and both report it as
`TDB_ERR_INVALID_ARGS` — the same code a malformed configuration produces. Without this call there
is no way to tell those two apart.

Opening a database written by a build that *did* have the codec is a different matter and is
allowed: the family's stored configuration is accepted so the database opens, and the gap surfaces
as a read error only if a node encoded with that algorithm is actually read.

### Parameters

| Parameter | Description |
| --- | --- |
| `type` | The algorithm to query. |

### Return Value

`1` if this build can both compress and decompress with the algorithm, `0` otherwise.

### Thread Safety

Safe to call from any thread at any time. It reads only build-time state and takes no locks.

### Examples

```c
tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

if (tidesdb_compression_available(TDB_COMPRESS_ZSTD))
{
    cf_config.encoding_pipeline[0] = (uint8_t)TDB_COMPRESS_ZSTD;
    cf_config.encoding_count = 1;
}

int rc = tidesdb_create_column_family(db, "events", &cf_config);
```

### See Also

[`tidesdb_create_column_family`](#tidesdb_create_column_family),
[`tidesdb_cf_update_runtime_config`](#tidesdb_cf_update_runtime_config)

## tidesdb_create_column_family

Create a column family.

### Synopsis

```c
int tidesdb_create_column_family(tidesdb_t *db, const char *name,
                                 const tidesdb_column_family_config_t *config);
```

### Description

Serializes the family's configuration and registers it in the manifest before publishing it in
memory. No directory is created -- a family's key logs live in the database directory and name their
family by id. The order matters: the manifest commit happens
first, so a crash cannot leave a live family the manifest does not know about.

The `name` argument is authoritative. Whatever `config->name` holds is overwritten with
`name` before the config is stored, so the two can never disagree on disk.

If `config->commit_hook_fn` is set, the hook is registered as part of the create. See
[`tidesdb_cf_set_commit_hook`](#tidesdb_cf_set_commit_hook).

The config is borrowed and may be freed as soon as the call returns.

### Parameters

| Parameter | Description |
| --- | --- |
| `db` | Database handle |
| `name` | Family name, non-empty, at most `TDB_MAX_CF_NAME_LEN` (128) bytes including the terminator |
| `config` | Configuration, borrowed. Its `name` field is ignored. |

### Errors

| Code | Cause |
| --- | --- |
| `TDB_ERR_INVALID_ARGS` | `db`, `name`, or `config` is `NULL`; `name` is empty; or the configuration failed validation |
| `TDB_ERR_INVALID_DB` | The database is closing |
| `TDB_ERR_EXISTS` | A family with this name already exists |
| `TDB_ERR_MEMORY` | Allocation failed |
| `TDB_ERR_IO` | The manifest record could not be written or committed |

An invalid configuration is reported as `TDB_ERR_INVALID_ARGS`, not as a distinct code, so
it is indistinguishable from a `NULL` argument by return value alone. The log records which
field was rejected.

### Thread Safety

Safe to call concurrently with other operations on the same database, including creates of
differently named families.

### Examples

```c
tidesdb_column_family_config_t cfg = tidesdb_default_column_family_config();
cfg.keep_values_inline  = 1;   /* scanned constantly, keep values whole */
cfg.enable_bloom_filter = 1;

int rc = tidesdb_create_column_family(db, "events", &cfg);
if (rc == TDB_ERR_EXISTS)
    rc = TDB_SUCCESS;             /* already there, fine */
```

### See Also

[`tidesdb_drop_column_family`](#tidesdb_drop_column_family),
[`tidesdb_get_column_family`](#tidesdb_get_column_family)

## tidesdb_drop_column_family

Drop a column family and delete its data.

### Synopsis

```c
int tidesdb_drop_column_family(tidesdb_t *db, const char *name);
```

### Description

Removes the family from the registry and the manifest and deletes its sstables. **This
destroys data and is not reversible.**

The call **waits** for any in-progress compaction on that family to finish before
proceeding, polling until the family is quiet. A family under heavy compaction can
therefore make this call take a while.

Any column family handle previously obtained for this family is invalid once the drop
returns. Using one afterwards is undefined behaviour.

### Parameters

| Parameter | Description |
| --- | --- |
| `db` | Database handle |
| `name` | Family to drop |

### Errors

| Code | Cause |
| --- | --- |
| `TDB_ERR_INVALID_ARGS` | `db` or `name` is `NULL` |
| `TDB_ERR_NOT_FOUND` | No family with that name |
| `TDB_ERR_IO` | The manifest could not be updated, or files could not be removed |

### Thread Safety

Safe to call concurrently, but the caller is responsible for ensuring no transaction or
iterator is still using the family being dropped.

### See Also

[`tidesdb_create_column_family`](#tidesdb_create_column_family)

## tidesdb_rename_column_family

Rename a column family.

### Synopsis

```c
int tidesdb_rename_column_family(tidesdb_t *db, const char *old_name, const char *new_name);
```

### Description

Renames the family, atomically with respect to readers.

**It moves no files.** A family's files are named for its immutable id rather than its name (see
[Formats](/appendix/formats#files-in-a-database-directory)), so a rename changes the registry index
and the persisted configuration and nothing else. Nothing on disk moves, there is no flush to drain
first, and no rebuilding of the family's open sstables — writers and readers run through it
untouched. Measured on a live database it is on the order of tens of microseconds, and commits keep
landing across it.

It still claims the family against the compaction scheduler, so that a concurrent DDL or planner
pass cannot read the configuration while it is replaced. That is a bounded wait, not an indefinite
one: if a compaction holds the family for the whole window (up to about 60 seconds), the call gives
up and reports `TDB_ERR_LOCKED`.

### Parameters

| Parameter | Description |
| --- | --- |
| `db` | Database handle |
| `old_name` | Current name |
| `new_name` | New name, at most `TDB_MAX_CF_NAME_LEN` bytes |

### Errors

| Code | Cause |
| --- | --- |
| `TDB_ERR_INVALID_ARGS` | `db`, `old_name`, or `new_name` is `NULL` |
| `TDB_ERR_NOT_FOUND` | No family named `old_name` |
| `TDB_ERR_EXISTS` | A family named `new_name` already exists |
| `TDB_ERR_LOCKED` | The family stayed busy with compaction for the whole quiesce window |
| `TDB_ERR_IO` | The manifest update failed |

### Thread Safety

Safe to call concurrently, and it does not stall writers. Because nothing on disk has to be kept
in step with the name, a rename drains no flush and blocks no committer; it claims the family only
so a second DDL and the compaction scheduler cannot act on it mid-update.

### See Also

[`tidesdb_clone_column_family`](#tidesdb_clone_column_family)

## tidesdb_clone_column_family

Copy a column family to a new name.

### Synopsis

```c
int tidesdb_clone_column_family(tidesdb_t *db, const char *src_name, const char *dst_name);
```

### Description

Creates `dst_name` as a copy of `src_name`, copying the source's sstables. It claims the source
family and, unlike a rename, **flushes the database memtable** first — it copies files, so
everything written before the call has to be in one, rather than only what had already reached
disk.

The destination inherits the source's configuration, minus the commit hook: a hook is a runtime
registration rather than persisted state, so a clone does not acquire one.

The clone is a point-in-time copy. Writes to the source after it returns do not appear in
the destination.

Because it copies sstables, the cost is proportional to the source family's on-disk size
and it needs that much free space.

### Parameters

| Parameter | Description |
| --- | --- |
| `db` | Database handle |
| `src_name` | Family to copy from |
| `dst_name` | Name for the new family; must not already exist |

### Errors

| Code | Cause |
| --- | --- |
| `TDB_ERR_INVALID_ARGS` | `db`, `src_name`, or `dst_name` is `NULL` |
| `TDB_ERR_NOT_FOUND` | No family named `src_name` |
| `TDB_ERR_EXISTS` | A family named `dst_name` already exists |
| `TDB_ERR_LOCKED` | The source stayed busy with compaction for the whole quiesce window |
| `TDB_ERR_IO` | The flush, a file copy, or the manifest update failed |
| `TDB_ERR_MEMORY` | Allocation failed |

### Thread Safety

Safe to call concurrently. Unlike rename, a clone does copy files, so it flushes the database memtable first and stalls flushes while it runs.

### See Also

[`tidesdb_rename_column_family`](#tidesdb_rename_column_family),
[`tidesdb_backup`](/reference/maintenance#tidesdb_backup)

## tidesdb_get_column_family

Look up a column family handle.

### Synopsis

```c
tidesdb_column_family_t *tidesdb_get_column_family(tidesdb_t *db, const char *name);
```

### Description

Returns the handle for `name`, or `NULL` if there is no such family. The handle is
**borrowed** — owned by the database, valid until that family is dropped or the database is
closed. Do not free it.

`NULL` is returned both for "no such family" and for a `NULL` argument; the two are not
distinguishable.

### Parameters

| Parameter | Description |
| --- | --- |
| `db` | Database handle |
| `name` | Family name |

### Return Value

The handle, or `NULL`.

### Thread Safety

Safe to call concurrently. The returned handle is safe to use from several threads, subject
to the rules of whatever call you pass it to.

### See Also

[`tidesdb_list_column_families`](#tidesdb_list_column_families),
[`tidesdb_txn_begin_cf`](/reference/transaction#tidesdb_txn_begin_cf)

## tidesdb_list_column_families

List every column family name.

### Synopsis

```c
int tidesdb_list_column_families(tidesdb_t *db, char ***names, int *count);
```

### Description

Allocates an array of newly allocated name strings. **The caller owns both levels** — free
each name, then the array itself, using [`tidesdb_free`](/reference/database#tidesdb_free)
rather than your own `free`, because the engine may be built against a different allocator.

A database with no families yields `TDB_SUCCESS`, `*names == NULL`, and `*count == 0`. Guard
the free loop accordingly.

### Parameters

| Parameter | Description |
| --- | --- |
| `db` | Database handle |
| `names` | Out. Receives the array. |
| `count` | Out. Receives the number of names. |

### Errors

| Code | Cause |
| --- | --- |
| `TDB_ERR_INVALID_ARGS` | `db`, `names`, or `count` is `NULL` |
| `TDB_ERR_MEMORY` | Allocation failed; nothing is returned and there is nothing to free |

### Thread Safety

Safe to call concurrently. The snapshot is taken under a read lock, so the list is
consistent, but a family may be created or dropped before you act on it.

### Examples

```c
char **names = NULL;
int count = 0;

if (tidesdb_list_column_families(db, &names, &count) == TDB_SUCCESS)
{
    for (int i = 0; i < count; i++)
    {
        printf("%s\n", names[i]);
        tidesdb_free(names[i]);
    }
    tidesdb_free(names);
}
```

### See Also

[`tidesdb_get_column_family`](#tidesdb_get_column_family)

## tidesdb_cf_update_runtime_config

Change a column family's configuration while it is open.

### Synopsis

```c
int tidesdb_cf_update_runtime_config(tidesdb_t *db, tidesdb_column_family_t *cf,
                                     const tidesdb_column_family_config_t *new_config,
                                     int persist_to_disk);
```

### Description

Applies a new configuration to a live family. **Every field may change**, including ones
that affect how data is written, because byte-wise key ordering means sstables written
under different settings remain mergeable. Existing sstables are not rewritten; the new
settings apply to what is written from now on.

The family's name and id are preserved — the incoming `name` is ignored. Renaming is
[`tidesdb_rename_column_family`](#tidesdb_rename_column_family).

With `persist_to_disk` non-zero the new configuration is written to the manifest and
survives a restart. With zero it applies in memory only and is lost on close.

The new configuration is published whole. A flush or compaction already building an sstable
continues against the configuration it started with, and the next one picks up the new one —
readers of the configuration never see a mixture of the two.

The call **fails fast** rather than waiting: if another exclusive operation holds the family it
returns `TDB_ERR_LOCKED` immediately. That is about ordering two writers, not about protecting
readers — two reconfigures racing could otherwise install one configuration and persist the other.
It returns rather than waits because the holder may be a compaction that runs for minutes, and
parking the caller behind one is worse than telling it the family is busy. Retry.

### Parameters

| Parameter | Description |
| --- | --- |
| `db` | Database handle |
| `cf` | Family handle from [`tidesdb_get_column_family`](#tidesdb_get_column_family) |
| `new_config` | Configuration to apply, borrowed; its `name` is ignored |
| `persist_to_disk` | 1 to persist in the manifest, 0 for in-memory only |

### Errors

| Code | Cause |
| --- | --- |
| `TDB_ERR_INVALID_ARGS` | A `NULL` argument, or the configuration failed validation |
| `TDB_ERR_LOCKED` | Another exclusive operation holds the family — retry |
| `TDB_ERR_IO` | `persist_to_disk` was set and the manifest write failed |

### Thread Safety

Safe to call concurrently, though two concurrent updates to the same family will see one of
them take `TDB_ERR_LOCKED`.

### See Also

[`tidesdb_default_column_family_config`](#tidesdb_default_column_family_config)

## tidesdb_cf_set_commit_hook

Set or clear a column family's commit hook.

### Synopsis

```c
int tidesdb_cf_set_commit_hook(tidesdb_t *db, tidesdb_column_family_t *cf,
                               tidesdb_commit_hook_fn fn, void *ctx);
```

### Description

Installs a callback invoked when a transaction touching this family commits, which is how
change data capture is built on TidesDB. Passing `NULL` for `fn` disables it.

The hook receives the committed operations as an array of `tidesdb_commit_op_t` along with
the context pointer given here. It runs on the committing thread, so it is on the write
path — work done inside it is latency every writer pays.

A hook may also be supplied at create time through the configuration's `commit_hook_fn`,
which is equivalent to calling this immediately after
[`tidesdb_create_column_family`](#tidesdb_create_column_family). It is a runtime registration
rather than persisted state, so it does not survive a reopen and a
[clone](#tidesdb_clone_column_family) does not inherit one.

**A hook cannot fail the commit.** It fires after the batch is durable and visible, so there is
nothing left to undo; a non-zero return is logged and otherwise ignored. Anything the hook must not
lose has to be made durable by the hook itself.

Each touched family's hook fires once, with only that family's operations, so a transaction
spanning several families invokes several hooks.

### Callback

```c,no-compile
typedef int (*tidesdb_commit_hook_fn)(const tidesdb_commit_op_t *ops, int num_ops,
                                      uint64_t commit_seq, void *ctx);
```

It fires after the WAL write, the memtable apply, and the commit-status marking have completed,
receiving that family's whole batch atomically. Returning non-zero is logged as a warning and
changes nothing else.

| Argument | Description |
| --- | --- |
| `ops` | The committed operations, valid only for the duration of the call |
| `num_ops` | Number of entries in `ops` |
| `commit_seq` | Monotonic commit sequence number assigned to the batch |
| `ctx` | The context pointer registered alongside the hook |

Each entry is a `tidesdb_commit_op_t`:

| Field | Description |
| --- | --- |
| `key` | Key data |
| `key_size` | Size of `key` in bytes |
| `value` | Value data, `NULL` for a delete |
| `value_size` | Size of `value` in bytes, `0` for a delete |
| `ttl` | Absolute expiry as a Unix timestamp, or `-1` when the pair never expires |
| `is_delete` | `1` for a delete, `0` for a put |

Two details matter for anything forwarding these operations elsewhere. The key and value pointers
address engine memory that is reused once the callback returns, so a hook that retains either must
copy it. And `ttl` is the deadline the engine stored, not the lifetime in seconds that
[`tidesdb_txn_put`](/reference/transaction#tidesdb_txn_put) was given — forwarding it verbatim
reproduces the same expiry instant instead of restarting the clock at the far end.

### Parameters

| Parameter | Description |
| --- | --- |
| `db` | Database handle |
| `cf` | Family handle |
| `fn` | Callback, or `NULL` to disable |
| `ctx` | Context passed through to the callback; the engine does not interpret or free it |

### Errors

| Code | Cause |
| --- | --- |
| `TDB_ERR_INVALID_ARGS` | `db` or `cf` is `NULL` |

### Thread Safety

Safe to call concurrently. Clearing a hook does not wait for an in-flight invocation to
finish, so the callback and its context must remain valid until the caller has established
by its own means that no commit is in progress.

### See Also

[`tidesdb_txn_commit`](/reference/transaction#tidesdb_txn_commit)
