---
title: On-Disk Formats
description: The byte layouts of every file the database writes.
slug: appendix/formats
part: appendix
sidebar:
  order: 2
---

# On-Disk Formats

This appendix documents the layouts as of format version 10.

Five structures carry that version and validate it on read: the block-manager file header, the
write-ahead log record, the sstable footer, the manifest record, and a column family's stored
configuration. Two carry no version of their own and are governed by whichever of those encloses
them — a btree node by its sstable's footer, a value-log block by its segment's file header. The
partition range filter directory is the exception: it versions independently, as noted where it is
described below.

:::caution[Descriptive, not a contract]
These layouts are documented so the engine can be understood, debugged, and its files inspected.
They are **not** a stability guarantee for third-party readers or writers. What is guaranteed is
stated in `VERSIONING.md`: a release reads what prior releases in its major line wrote. Anything
beyond that — parsing these files with your own tooling — is at your own risk and may break in a
minor release.
:::

All multi-byte integers are **little-endian** unless a table says otherwise. The sstable footer
is the exception and is noted where it occurs.

## Files in a database directory

| File | Contents |
| --- | --- |
| `MANIFEST` | The catalogue: which families and sstables exist |
| `NNNNNNN.vlog` | One append-only segment of the shared value log holding separated values; exactly one is open for appends and the rest are immutable. Each value's block records the whole chain of encodings it was written through, so one store serves families with different pipelines and a value survives being carried into an sstable configured differently |
| `NNNNNNN.log` | A write-ahead log generation, zero-padded to 7 digits |
| `CCCCCCCCCC.SSSSSSS.klog` | An sstable's key log: its family's id zero-padded to ten digits, a dot, then the sstable id zero-padded to seven |
| `CCCCCCCCCC.SSSSSSS.klog.lstmp` | Transient. Where a build stages uncompressed leaves before encoding them, so it exists only while an sstable is being written and only when the family has an encoding pipeline. It is removed when the build ends, whether it succeeded or failed; only a crash leaves one behind, and the next open sweeps it alongside the orphaned key logs |

Every one is a block-manager file and shares the framing below.

**Families have no directory of their own.** Every file above sits directly in the database
directory, and a key log names its owning family in its own filename, by **id** rather than by name.
The id is assigned once and never reused, so a family's files never move. That is what makes
[`tidesdb_rename_column_family`](/reference/column-family#tidesdb_rename_column_family) a change of
name and nothing else — nothing on disk moves, and so none of the open sstables whose cached paths a
move would invalidate need rebuilding. Mapping an id back to a family name means reading the
`MANIFEST`, which is the catalogue for everything else on disk too.

Carrying the family id in the filename is also what lets a database whose `MANIFEST` is unreadable be
rebuilt from the key logs alone: the files still say which family each belongs to.

## The block frame

Every record in every file:

```
  offset  size  field
  ------  ----  ---------------------------------------------
       0     4  payload size          (uint32, little-endian)
       4     4  payload checksum      (XXH3, truncated to 32 bits)
       8     n  payload
     8+n     4  payload size again    (uint32, little-endian)
    12+n     4  footer magic 0x42445442  ("BTDB" reversed)
```

The size appearing at **both ends**, plus the footer magic, is what makes a partially written
record detectable without a separate intentions log. A record whose trailing size disagrees with
its leading one, or whose magic is missing, was never completely written.

A payload size of **zero is invalid** and is rejected at write time. Readers treat a zero size
field as end-of-file, so permitting one would truncate iteration for everything after it.

## The file header

Every block-manager file begins with 8 bytes:

```
  offset  size  field
  ------  ----  ---------------------------------
       0     3  magic 0x544442 ("TDB")
       3     1  format version (10)
       4     4  reserved
```

## Write-ahead log record

One framed block per committed batch. The payload:

```
  1 byte    format version (10)
  1 byte    record kind
  varint    xid length (0 when absent)
  n bytes   xid
  varint    entry count
  then, per entry:
    1 byte  flags
    varint  column family index
    varint  sequence
    varint  key size
    varint  value size
    varint  ttl            (present only when the HAS_TTL flag is set)
    varint  value log id   (present only when the VLOG_REF flag is set)
    n bytes key            (the interval's lower bound for a range delete)
    n bytes value          (absent when the VLOG_REF flag is set; the interval's exclusive upper
                            bound for a range delete, and empty for an open one)
```

**Record kinds**

| Value | Kind | Meaning |
| --- | --- | --- |
| 0 | `TDB_WAL_KIND_WRITE_BATCH` | An ordinary single-phase commit |
| 1 | `TDB_WAL_KIND_PREPARE` | Two-phase commit phase one: durable but not applied |
| 2 | `TDB_WAL_KIND_COMMIT` | Phase two, commit — carries the batch to apply |
| 3 | `TDB_WAL_KIND_ROLLBACK` | Phase two, abandon |
| 4 | `TDB_WAL_KIND_ABORT_SEQ` | Names an already-durable sequence that replay must not apply. The sequence rides in the xid slot as 8 big-endian bytes, so the record is the usual framing with an xid length of 8 and an entry count of 0. A distinct kind rather than a rollback, which is keyed by a caller's transaction id and could legitimately be 8 bytes long |

`TDB_WAL_KIND_ABORT_SEQ` exists because a write batch's presence in the log *is* its commitment, so a batch
that reached the log but failed to enter the memtable would otherwise come back on the next open
after its caller was told the transaction failed. Replay collects these first and skips the
sequences they name.

**Entry flags**

| Bit | Flag | Meaning |
| --- | --- | --- |
| 0x01 | `TOMBSTONE` | A delete; no value follows |
| 0x02 | `SINGLE_DELETE` | The delete supersedes at most one put |
| 0x04 | `HAS_TTL` | A ttl field is present for this entry |
| 0x08 | `VLOG_REF` | The value's bytes are in the value log, not in this record. A value log id follows the ttl slot and no value bytes follow the key; `value size` still carries the value's logical length, so a reader knows how large it is without a value log probe. An id of zero is refused rather than read as an empty value |
| 0x10 | `TDB_WAL_ENTRY_RANGE_DELETE` | The entry deletes every key in an interval rather than the one key it names. The key is the inclusive lower bound and the **value is the exclusive upper bound**, empty when the interval runs to the end of the column family. Always set alongside `TOMBSTONE`, so a reader that does not know this bit still sees a valueless delete rather than a live put |

Sequences are carried per entry, so replay applies each at the sequence it committed with
rather than at its position in the file.

Both optional fields are gated on a flag rather than always present, which is why adding the value
log reference did not move the format version: a record without the bit encodes and decodes exactly
as it always did.

## SSTable footer

The last block of a `.klog`. **Big-endian**, unlike everything else — it is read by a path that
predates the little-endian convention elsewhere.

Fixed head, 116 bytes:

```
  size  field
  ----  -----------------------------------------------
     4  magic 0x53535442 ("SSTB")
     4  format version (10)
     8  btree root offset
     8  first leaf offset
     8  last leaf offset
     8  filter directory offset
     4  filter directory size
     8  distinct key count
     8  tombstone count
     8  maximum sequence
     8  total key bytes
     8  total value bytes
     8  klog logical bytes
     8  btree node count
     8  range tombstone applied sequence
     4  btree height
     4  btree node size
```

The *range tombstone applied sequence* is the newest range tombstone this table's build could see
at the reclamation floor it ran at, and every one at or below it had already been applied to these
contents. The **minimum across a column family's tables** is what says a range tombstone has
nothing left to hide and can be retired. A table built before any range tombstone existed records
zero and holds that minimum down until it is rewritten, which is the conservative direction: the
value has to be a sequence the build actually observed, never the floor, or a table built before a
tombstone would claim to have applied it.

Then a variable tail:

```
     4  minimum key length
     n  minimum key
     4  maximum key length
     n  maximum key
     1  encoding count
     n  encoding pipeline ids
     4  value log reference count
    24  per reference: segment(8) + bytes(8) + count(8)
```

The value log references are how an sstable records which segments it draws separated values from
and how much of each it holds, which is what lets a reclaim decide a segment is worth draining
without reading every key log.

Every length in the tail is bounds-checked against the remaining bytes, so a truncated or lying
footer is rejected rather than read past.

Recording the **btree node size** here rather than reading it from configuration is what lets a
file be read with the geometry it was written with, after the configuration has changed.

## Partition range filter directory

The resident half of an sstable's filter, written into the key log's aux region and pointed at by
the footer's *filter directory offset* and *size*. Little-endian throughout:

```
  4 bytes  magic 0x46424254 ("TBBF")
  4 bytes  format version
  4 bytes  partition count
  then, per partition:
    8 bytes  blob offset within the key log
    4 bytes  blob size
    4 bytes  entry count
    4 bytes  first key length
    n bytes  first key
```

The records are in ascending key order, so a lookup binary-searches them to route a query to its
partition. The first keys are stored **whole** — an approximate routing could send a query to the
wrong partition and produce a false negative, which is worse than no filter at all.

:::note[This directory versions independently of the file holding it]
It carries its own magic and its own format version, validated on read, rather than inheriting the
key log's. So its version is **not** the format version at the top of this appendix, and it moves
only when this layout changes. The blobs it points at are ordinary bloom filters fetched on demand
through the block cache, which is what bounds the filter's resident cost to the directory alone.
:::

## BTree leaf node

```
  1 byte     node type
  varint     entry count
  8 bytes    previous leaf offset   (-1 when first)
  8 bytes    next leaf offset       (-1 when last)
  2n bytes   key offset table       (uint16 per entry, from the start of the keys section)
  varint     base sequence
  then, per entry:
    varint   shared prefix length
    varint   suffix length
    varint   value size
    varint   vlog offset            (0 when the value is inline)
    svarint  sequence delta from the base
    svarint  ttl
    1 byte   flags
  then:
    keys section     suffixes only, prefix-compressed
    values section   inline values, concatenated
```

Keys store only the suffix not shared with the preceding key. Sequences are deltas from a
per-node base. The offset table makes a search within a leaf a binary search rather than a walk.

A compressed node carries a 20-byte header ahead of its compressed payload — original size (4),
previous offset (8), next offset (8) — so the sibling links can be patched without decompressing.

## Value log block

```
  8 bytes  logical id
  8 bytes  value length, with the encoding count in the top byte
  c bytes  encoding pipeline ids, in the order they were applied
  n bytes  value, as stored
```

A value's length is bounded by the uint32 block frame, so the upper half of the length word was
never used; the top byte of it carries how many encodings the value was written through, and that
many ids follow the fixed header. A count of zero means the bytes are stored verbatim and no ids
follow.

**Every value describes its own encoding, and that is load-bearing rather than convenient.**
Compaction carries a separated value forward by id without re-reading or re-encoding it, so a value
written under one pipeline can end up referenced by an sstable whose footer records a different one.
A value described by anything other than its own bytes would then be decoded with the wrong chain.
It is also what lets one shared store hold values from families that encode differently.

Values are addressed by opaque logical id rather than by file offset, so which segment holds a value
is not baked into the sstables referencing it.

The store is a series of numbered segments rather than one file. The store never moves bytes itself:
a reclaim unlinks a segment nothing references any more, and a segment that is merely mostly-dead is
marked instead, so the next compaction carrying one of its values **writes that value afresh under a
new id** rather than keeping the reference. Nothing is ever copied within the store, so an id names
one block for its whole life and a crash cannot leave the same id in two segments — a pass has
either unlinked a segment or it has not.

## Manifest record

One framed block per commit, holding a batch:

```
  1 byte   format version
  then a sequence of records, each starting with a 1-byte opcode
```

| Opcode | Record | Size |
| --- | --- | --- |
| `MANIFEST_OP_CF_ADD` | op + cf id(8) + name len(2) + blob len(2), then name and blob | 13 + variable |
| `MANIFEST_OP_CF_DROP` | op + cf id(8) | 9 |
| `MANIFEST_OP_ADD_P` | op + cf(8) + level(4) + id(8) + entries(8) + bytes(8) + partition(4) + birth level(4) | 45 |
| `MANIFEST_OP_MOVE` | op + cf(8) + id(8) + new level(4) | 21 |
| `MANIFEST_OP_REMOVE` | op + cf(8) + level(4) + id(8) | 21 |
| `MANIFEST_OP_SEQ` | op + sequence(8) | 9 |
| `MANIFEST_OP_CF_SEQ` | op + next family id(8) | 9 |

Records are self-delimiting, so a batch is walked without an index. The column family
configuration blob is stored **verbatim and never interpreted** by the manifest.

A rollover writes a single snapshot batch — the family registry, every live sstable, each family's
range tombstone set, then `MANIFEST_OP_SEQ` and `MANIFEST_OP_CF_SEQ` — to a temp file that is then
atomically renamed over the manifest.

## Compatibility

`VERSIONING.md` holds the policy and the compatibility matrix. In summary: the on-disk format is
a first-class contract, a major release may change it and ships migration tooling, a minor
release may add a format only if it is opt-in and default-off so downgrade stays possible, and a
patch release may not change it at all.
