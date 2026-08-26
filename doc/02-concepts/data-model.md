---
title: Data Model
description: Keys, values, byte ordering, and column families.
slug: concepts/data-model
part: concepts
sidebar:
  order: 1
---

# Data Model

## Keys and values are bytes

A key is a byte string; a value is a byte string. The engine attaches no meaning to either — no
types, no schema, no encoding. A key may be any length above zero; a value may be empty.

This is the whole model, and everything else is a property of how those bytes are ordered and
when they are visible.

## Ordering is `memcmp`, always

Keys are ordered by unsigned byte comparison. There are no custom comparators, and this is a
deliberate design decision rather than a missing feature.

A pluggable comparator would have to be supplied identically on every open, forever, by every
process that touches the database. Supply a different one — a fixed bug, a changed locale, a
second application — and the sstables are no longer mergeable and the data is silently
misordered. The failure is catastrophic, delayed, and unattributable.

Byte ordering removes that class of failure entirely, and costs only that **you encode keys to
sort correctly**:

| To sort by | Encode as |
| --- | --- |
| Unsigned integer | Big-endian, fixed width |
| Signed integer | Big-endian with the sign bit flipped |
| Descending anything | Invert the bytes |
| Timestamp then id | Big-endian timestamp, then the id, concatenated |
| Text, case-insensitive | Normalise before storing |

A composite key is just concatenation, and because ordering is lexicographic, a prefix scan over
the leading component works with no extra machinery — which is what makes
[prefix iteration](/getting-started#prefix-scans) fall out for free.

## Column families

A database holds one or more **column families**, each an independent ordered keyspace. The same
key may exist in several families with different values.

Each family has its own on-disk levels, its own sstables, and its own compaction policy and
triggers, so families with different access patterns do not degrade each other: a
write-heavy family's compaction does not inflate a read-heavy family's read amplification.

What families **share** is what makes them cheap and what makes cross-family transactions
atomic: one memtable, one write-ahead log, one value log, one block cache, one sequence clock.

That sharing has visible consequences worth knowing before you design around families:

- A flush writes out **every** family's data, because there is one memtable.
- **Cloning** a family costs a database-wide flush, because a clone copies files and everything it
  should copy has to be in a file first. **Renaming** costs none: a family's key logs are named for
  its id rather than its name, so a rename moves nothing on disk and changes only the registry
  index and the persisted configuration.
- Configuration is per family; a family is the unit at which you tune node size, bloom filters and
  compaction triggers. Value separation is the exception: the size threshold is database-wide,
  because the value log is one shared store and the decision keys on how large a value is rather
  than on which family holds it. A family can opt out of it entirely with `keep_values_inline`.

Use families to separate data with **different shapes or access patterns** — small hot metadata
apart from large cold blobs, for instance. Do not use them as a substitute for key prefixes:
thousands of families are not the intended shape, and a prefix inside one family costs nothing.

Removing one of those prefixes costs nothing to write either.
[`tidesdb_txn_delete_prefix`](/reference/transaction#tidesdb_txn_delete_prefix) deletes every key
under a prefix as a single entry, so a tenant or a partition leaves in one operation rather than
one per key. The space it frees comes back when a compaction next rewrites the range, not at the
moment of the call.

A range whose bounds fall where no prefix could put them is
[`tidesdb_txn_delete_range`](/reference/transaction#tidesdb_txn_delete_range), which takes the two
bounds directly and costs the same single entry. The prefix form is that call with the one bound a
prefix implies, and it is the one to reach for when what you are removing genuinely is a prefix,
because it cannot get its bounds wrong.

## Versions

A write does not overwrite. It appends a new version of the key, stamped with the sequence its
transaction committed at, and older versions remain until compaction can prove nothing needs
them.

That is what makes a snapshot cheap — it is a number, not a copy — and it is why a reader never
blocks a writer. It is also why deleting data does not immediately free space: a delete writes a
**tombstone**, another version, which shadows what is beneath it until a merge can safely drop
both. See [Compaction](/internals/compaction).

A tombstone is the only thing that means *absent*. A value of **zero bytes is a value**: the key is
present and a read returns it with a size of zero rather than reporting it missing. That distinction
matters for anything whose meaning is carried entirely by the key — a secondary index entry, a set
member — which would otherwise have to store a filler byte it does not want.

## Application timestamps

The engine versions by **its own commit sequence**, and reading at a past sequence is what
[`tidesdb_txn_begin_at_seq`](/reference/transaction#tidesdb_txn_begin_at_seq) does. That answers
"what did the database look like then." It does not answer "what did the application mean at time
T," because the engine attaches no meaning to an application clock.

A timestamp you supply is carried **in the key**, and the `memcmp` ordering is what makes it work:

```
<id> | <inverted timestamp>
```

Invert the stamp — `UINT64_MAX - ts`, big-endian — so a newer version sorts **earlier**. Then the
newest version of an id is the first key under `<id>|`, and reading as of a moment is a plain seek:

| To read | Seek to |
| --- | --- |
| The latest version | `<id>\|` |
| The version as of T | `<id>\|` + `invert(T)` |

A seek lands on the first key at or after its target, so seeking to `invert(T)` lands on the
newest version whose stamp is at or before T. Seeking past the oldest version runs into whatever
sorts next, so **check that what you landed on still carries the id's prefix** before reading it
as a version — otherwise a neighbouring id answers in its place.

Retiring an id is then one operation, since all its versions share a prefix:

```c
/* every version of this id, however many accumulated */
tidesdb_txn_delete_prefix(txn, cf, (const uint8_t *)"doc|", 4);
```

Dropping versions older than a moment is a
[range delete](/reference/transaction#tidesdb_txn_delete_range) over that id's versions, since the
bound falls wherever the moment does rather than on a prefix boundary.

### What the two axes each give you

They compose, and it is worth being deliberate about which one answers which question. An iterator
is created against a transaction, and a transaction can be opened at a past sequence — so an "as
of T" seek can run **inside** a consistent point-in-time view of the store:

```c
/* the store as it stood at a sequence, and within it the application's own sense of time */
uint64_t seq = tidesdb_oldest_readable_seq(db);
tidesdb_txn_begin_at_seq(db, seq, &txn);
tidesdb_iter_new(txn, cf, &it);
```

The sequence gives cross-key consistency, which an application timestamp cannot on its own — two
keys stamped independently were not necessarily written together. The stamp gives meaning the
engine's sequence does not carry.

What this costs, against an engine that understood the timestamp natively:

- Reading the latest version is a **seek rather than a get**, so it does not take the bloom
  filter's exact-key path.
- Old versions live until you delete them. The engine will not collapse them by stamp, only by
  sequence once nothing can read them.
- A scan across many ids at one moment has to **fold by id as it walks**, because the engine merges
  by key and each version is a distinct key.

## Expiry

An entry may carry an expiry. Once the clock passes it, the entry reads as absent
everywhere, and the space is reclaimed by a later compaction — visibility is prompt,
reclamation is lazy.

The clock is a second-granular one the engine publishes on a tick, so an entry stops being visible
within about a second of its deadline rather than at the instant it passes. Every source compares
against that same published second, so a key never appears to expire in one place and not another.

The expiry is given as a **lifetime in seconds**, and the engine converts it to an absolute
deadline at the moment of the `put`. Zero or negative never expires.

## Limits

| Limit | Value |
| --- | --- |
| Column family name | 128 bytes including the terminator |
| Levels per family | 8 |
| Encoding pipeline stages | 8 |
| Key size | Non-zero, and under 4 GiB — the sstable node records a key's length in a `uint32` |
| Value size | Under 4 GiB, and otherwise bounded by memory. A separated value is bounded by the block frame instead — its stored bytes plus a small header must fit a `uint32` — and an inline one by the same node field a key uses |
