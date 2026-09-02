---
title: Iterator Operations
description: Ordered forward and backward traversal of a column family at a transaction snapshot.
slug: reference/iterator
part: reference
sidebar:
  order: 4
---

# Iterator Operations

An iterator walks one column family in byte order at a transaction's snapshot. It merges
every source that can hold a version of a key — the transaction's own buffered writes, the
active memtable, the sealed memtables awaiting flush, and each level's sstables — and
presents the newest version visible at the snapshot, hiding tombstones and expired entries.

An iterator is stable: sstables merged or deleted by a compaction while you are iterating do not
disturb it, and writes committed by other transactions after its snapshot do not appear.

Which snapshot it reads at follows the transaction's isolation level, matching what a point read
in the same transaction would see:

| Isolation | The iterator reads at |
| --- | --- |
| `TDB_ISOLATION_REPEATABLE_READ`, `TDB_ISOLATION_SNAPSHOT`, `TDB_ISOLATION_SERIALIZABLE` | The transaction's snapshot, taken at begin — every scan in the transaction sees one instant |
| `TDB_ISOLATION_READ_COMMITTED` | The current sequence, taken when the iterator is created — everything committed before that moment, so two scans in one transaction may legitimately differ |
| `TDB_ISOLATION_READ_UNCOMMITTED` | Everything, including versions other transactions have written but not committed |

Iterators are **not thread-safe**. One iterator belongs to one thread, and it must be freed
before the transaction it was created from is freed.

## Direction changes are supported but not free

The iterator is bidirectional: you may call [`tidesdb_iter_prev`](#tidesdb_iter_prev) after
[`tidesdb_iter_next`](#tidesdb_iter_next) and the sequence stays correct. Reversing forces
every source to re-seek to the current position, because a source that was exhausted in the
old direction has to be brought back into play. Scans that flip direction repeatedly pay
that cost each time; scans that go one way do not.

## tidesdb_iter_new

Create an iterator.

### Synopsis

```c
int tidesdb_iter_new(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, tidesdb_iter_t **iter);
```

### Description

Creates an iterator over `cf` at `txn`'s snapshot. The iterator starts **unpositioned** —
call one of the seek functions before reading. Calling
[`tidesdb_iter_valid`](#tidesdb_iter_valid) first returns 0.

The iterator borrows the transaction. Free it with
[`tidesdb_iter_free`](#tidesdb_iter_free) before
[`tidesdb_txn_free`](/reference/transaction#tidesdb_txn_free).

### Errors

| Code | Cause |
| --- | --- |
| `TDB_ERR_INVALID_ARGS` | `txn`, `cf`, or `iter` is `NULL` |
| `TDB_ERR_MEMORY` | Allocation failed |
| `TDB_ERR_LOCKED` | The descriptor budget or a source set moving under a compaction left the scan unopenable. The engine waits such pressure out, so this is the rare case where it did not clear — retry, and never read it as an empty family |
| `TDB_ERR_IO` / `TDB_ERR_CORRUPTION` | A source could not be opened or did not decode |

### See Also

[`tidesdb_iter_seek_to_first`](#tidesdb_iter_seek_to_first)

## tidesdb_iter_new_range

Create an iterator over a known key range.

### Synopsis

```c
int tidesdb_iter_new_range(tidesdb_txn_t *txn, tidesdb_column_family_t *cf, const uint8_t *lower,
                           size_t lower_size, const uint8_t *upper, size_t upper_size,
                           tidesdb_iter_t **iter);
```

### Description

Creates an iterator over the part of `cf` between `lower` and `upper`, at `txn`'s snapshot.
Like [`tidesdb_iter_new`](#tidesdb_iter_new) it starts **unpositioned**.

The difference is what it costs. An iterator holds one open cursor per sstable that could
answer it, descends each of them on every seek, and compares each of them on every step — so
an unbounded scan of a family holding hundreds of sstables pays for all of them even when it
reads three rows. Given the range up front, the iterator leaves out every sstable whose own
key range cannot meet it. On a family of 32 sstables holding disjoint bands, a four-row scan
went from 128 block cache lookups to 4.

This is the difference between range scans that scale with concurrency and range scans that
do not: many narrow scans running at once otherwise each contend for the whole store.

:::caution[The range is a promise, not a fence]
Results are defined **only inside the range**. The sstables that could answer outside it were
never opened, so seeking or stepping past either end may report a key absent that exists. The
iterator does not stop you at the bound and does not report one — the caller stops itself.
Use [`tidesdb_iter_new`](#tidesdb_iter_new) when the extent is not known in advance.
:::

`upper` is treated as inclusive when choosing sstables, so a caller holding an exclusive end
may pass it unchanged; at worst one sstable is kept that the scan never reads from.

### Errors

| Code | Cause |
| --- | --- |
| `TDB_ERR_INVALID_ARGS` | `txn`, `cf`, `iter`, `lower`, or `upper` is `NULL` — both ends are required, since one end alone leaves nothing to test an sstable against |
| `TDB_ERR_MEMORY` | Allocation failed |
| `TDB_ERR_LOCKED` | As [`tidesdb_iter_new`](#tidesdb_iter_new) — retry, and never read it as an empty range |
| `TDB_ERR_IO` / `TDB_ERR_CORRUPTION` | A source could not be opened or did not decode |

### Examples

```c
/* rows from "order:1000" up to "order:2000" */
tidesdb_iter_t *it = NULL;
if (tidesdb_iter_new_range(txn, cf, (const uint8_t *)"order:1000", 10,
                           (const uint8_t *)"order:2000", 10, &it) == TDB_SUCCESS)
{
    tidesdb_iter_seek(it, (const uint8_t *)"order:1000", 10);

    while (tidesdb_iter_valid(it))
    {
        uint8_t *k = NULL; size_t klen = 0;
        if (tidesdb_iter_key(it, &k, &klen) != TDB_SUCCESS) break;

        /* the caller stops at its own upper bound, the iterator does not */
        const int past_end = (klen >= 10 && memcmp(k, "order:2000", 10) > 0);
        tidesdb_free(k);
        if (past_end) break;

        tidesdb_iter_next(it);
    }
    tidesdb_iter_free(it);
}
```

### See Also

[`tidesdb_iter_new`](#tidesdb_iter_new), [`tidesdb_range_stats`](/reference/statistics#tidesdb_range_stats)

## tidesdb_iter_seek

Position at the first key `>=` the given key.

### Synopsis

```c
int tidesdb_iter_seek(tidesdb_iter_t *iter, const uint8_t *key, size_t key_size);
```

### Description

Positions at the first key greater than or equal to `key`. If no such key exists the
iterator becomes invalid, which is the normal way a forward scan ends.

Combined with a prefix check on each key, this is how prefix scans are done — seek to the
prefix, then walk forward while the key still starts with it.

### Errors

| Code | Cause |
| --- | --- |
| `TDB_ERR_NOT_FOUND` | No key qualifies; the iterator is left invalid. This is how a scan ends, not a fault |
| `TDB_ERR_INVALID_ARGS` | A `NULL` argument or a zero-length key |
| `TDB_ERR_LOCKED` | Descriptor pressure kept a source from being read — retry |
| `TDB_ERR_IO` / `TDB_ERR_CORRUPTION` / `TDB_ERR_MEMORY` | A source read failed |

### Examples

```c
/* every key beginning with "user:" */
tidesdb_iter_seek(it, (const uint8_t *)"user:", 5);

while (tidesdb_iter_valid(it))
{
    uint8_t *k = NULL; size_t klen = 0;
    if (tidesdb_iter_key(it, &k, &klen) != TDB_SUCCESS) break;

    const int in_prefix = (klen >= 5 && memcmp(k, "user:", 5) == 0);
    tidesdb_free(k);
    if (!in_prefix) break;

    tidesdb_iter_next(it);
}
```

## tidesdb_iter_seek_for_prev

Position at the last key `<=` the given key.

### Synopsis

```c
int tidesdb_iter_seek_for_prev(tidesdb_iter_t *iter, const uint8_t *key, size_t key_size);
```

### Description

The mirror of [`tidesdb_iter_seek`](#tidesdb_iter_seek), for starting a backward scan at or
before a key. If every key is greater than `key` the iterator becomes invalid.

### Errors

Same as [`tidesdb_iter_seek`](#tidesdb_iter_seek).

## tidesdb_iter_seek_to_first

Position at the first key.

### Synopsis

```c
int tidesdb_iter_seek_to_first(tidesdb_iter_t *iter);
```

### Description

Positions at the smallest visible key. An empty column family leaves the iterator invalid and
reports `TDB_ERR_NOT_FOUND`.

### Errors

As [`tidesdb_iter_seek`](#tidesdb_iter_seek), less the key arguments: `TDB_ERR_NOT_FOUND` when
the family has no visible key, `TDB_ERR_INVALID_ARGS` if `iter` is `NULL`, `TDB_ERR_LOCKED` under
descriptor pressure, and `TDB_ERR_IO`, `TDB_ERR_CORRUPTION` or `TDB_ERR_MEMORY` from a source read.

## tidesdb_iter_seek_to_last

Position at the last key.

### Synopsis

```c
int tidesdb_iter_seek_to_last(tidesdb_iter_t *iter);
```

### Description

Positions at the largest visible key, for a backward scan. An empty column family leaves the
iterator invalid.

### Errors

Same as [`tidesdb_iter_seek_to_first`](#tidesdb_iter_seek_to_first).

## tidesdb_iter_next

Advance to the next key.

### Synopsis

```c
int tidesdb_iter_next(tidesdb_iter_t *iter);
```

### Description

Moves forward one key. Advancing past the last key makes the iterator invalid and reports
`TDB_ERR_NOT_FOUND`; this is the normal end of a scan rather than a fault, and
[`tidesdb_iter_valid`](#tidesdb_iter_valid) is how you detect it. Do not use the return value as
the loop condition — check `valid` instead.

### Errors

Same as [`tidesdb_iter_seek`](#tidesdb_iter_seek), less the argument checks that do not apply:
`TDB_ERR_NOT_FOUND` at the end of the stream, `TDB_ERR_INVALID_ARGS` if `iter` is `NULL`,
`TDB_ERR_LOCKED` under descriptor pressure, and `TDB_ERR_IO`, `TDB_ERR_CORRUPTION` or
`TDB_ERR_MEMORY` from a source read.

## tidesdb_iter_prev

Step to the previous key.

### Synopsis

```c
int tidesdb_iter_prev(tidesdb_iter_t *iter);
```

### Description

Moves back one key, becoming invalid when stepped before the first. See
[Direction changes](#direction-changes-are-supported-but-not-free) for the cost of
alternating with [`tidesdb_iter_next`](#tidesdb_iter_next).

### Errors

Same as [`tidesdb_iter_next`](#tidesdb_iter_next).

## tidesdb_iter_valid

Report whether the iterator is on a live key.

### Synopsis

```c
int tidesdb_iter_valid(tidesdb_iter_t *iter);
```

### Description

Returns 1 when the iterator is positioned on a readable key and 0 otherwise — before the
first seek, after running off either end, or for a `NULL` iterator. This is the loop
condition for every scan.

### Return Value

1 if valid, 0 otherwise. It cannot fail and reports no errors, so a source read failure
during a `next` shows up as invalidity here rather than as a distinct signal; check the
return value of the movement call if you need to tell the two apart.

## tidesdb_iter_key

Read the key at the current position.

### Synopsis

```c
int tidesdb_iter_key(tidesdb_iter_t *iter, uint8_t **key, size_t *key_size);
```

### Description

Returns a **newly allocated** copy of the current key. Free it with
[`tidesdb_free`](/reference/database#tidesdb_free). The copy is independent of the iterator
and stays valid after moving or freeing it.

### Errors

| Code | Cause |
| --- | --- |
| `TDB_ERR_NOT_FOUND` | The iterator is not positioned on a key — before the first seek, or after running off either end |
| `TDB_ERR_INVALID_ARGS` | A `NULL` argument |
| `TDB_ERR_MEMORY` | Allocation failed |

Note that "not positioned" is `TDB_ERR_NOT_FOUND`, not `TDB_ERR_INVALID_ARGS`. Ordinarily
[`tidesdb_iter_valid`](#tidesdb_iter_valid) is checked first and neither arises.

## tidesdb_iter_value

Read the value at the current position.

### Synopsis

```c
int tidesdb_iter_value(tidesdb_iter_t *iter, uint8_t **value, size_t *value_size);
```

### Description

Returns a **newly allocated** copy of the current value, freed with
[`tidesdb_free`](/reference/database#tidesdb_free).

A value stored in the value log rather than inline is fetched here, so this call can cost an
extra read that [`tidesdb_iter_key`](#tidesdb_iter_key) does not. A scan that only needs keys
should not call it — that is most of the benefit of key/value separation.

### Errors

Same as [`tidesdb_iter_key`](#tidesdb_iter_key), plus `TDB_ERR_IO` or `TDB_ERR_CORRUPTION`
if a separated value cannot be read back.

## tidesdb_iter_key_value

Read both in one call.

### Synopsis

```c
int tidesdb_iter_key_value(tidesdb_iter_t *iter, uint8_t **key, size_t *key_size,
                           uint8_t **value, size_t *value_size);
```

### Description

Equivalent to calling [`tidesdb_iter_key`](#tidesdb_iter_key) and
[`tidesdb_iter_value`](#tidesdb_iter_value), returning both as newly allocated buffers.
**Both** must be freed with [`tidesdb_free`](/reference/database#tidesdb_free).

On failure neither is written, so there is nothing to free after an error.

### Errors

Same as [`tidesdb_iter_value`](#tidesdb_iter_value).

### Examples

```c
tidesdb_iter_t *it = NULL;
if (tidesdb_iter_new(txn, cf, &it) != TDB_SUCCESS) return TDB_ERR_MEMORY;

for (tidesdb_iter_seek_to_first(it); tidesdb_iter_valid(it); tidesdb_iter_next(it))
{
    uint8_t *k = NULL, *v = NULL;
    size_t klen = 0, vlen = 0;

    if (tidesdb_iter_key_value(it, &k, &klen, &v, &vlen) != TDB_SUCCESS) break;

    /* ... use k and v ... */

    tidesdb_free(k);
    tidesdb_free(v);
}

tidesdb_iter_free(it);
return TDB_SUCCESS;
```

## tidesdb_iter_free

Free an iterator.

### Synopsis

```c
void tidesdb_iter_free(tidesdb_iter_t *iter);
```

### Description

Releases the iterator and the source handles it holds. `NULL` is safe.

Free it before the transaction it came from. An iterator holds references that keep sstables
and sealed memtables alive, so one left open pins resources a flush or compaction would
otherwise reclaim — long-lived iterators hold back space.
