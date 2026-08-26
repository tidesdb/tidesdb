---
title: Block Manager
description: The framing, durability, preallocation, and buffered append ring that every file in the database goes through.
slug: internals/block-manager
part: internals
sidebar:
  order: 5
---

# Block Manager

## The problem

Every file TidesDB writes — the write-ahead logs, the sstable key logs, the value log, the
manifest — needs the same four things: a way to tell where one record ends and the next
begins, a way to detect a record that was damaged or half-written, a way to append
concurrently without threads serializing on each other, and a defined meaning for "durable".

Solving that once, in one module, is why a single recovery discipline covers every file in the
database. It is also why a torn tail in the manifest and a torn tail in a log are handled by
the same code.

## Framing

Every record is one framed block:

```
  [ size:4 ][ checksum:4 ][ ...payload... ][ size:4 ][ magic:4 ]
   \___________________/                   \__________________/
        header (8)                              footer (8)
```

The size appears **twice**, at both ends, and the footer carries a magic value. That
redundancy is what makes a partial write detectable without a separate log of intentions: a
record whose trailing size disagrees with its leading one, or whose footer magic is absent,
was never completely written. The checksum then covers the payload itself, catching damage
that arrived after a successful write.

The file itself opens with an 8-byte header carrying a magic value and a format version, so a
file that is not ours, or is from a format we do not speak, is rejected at open rather than
misread.

A zero size field is treated as end-of-file by every reader. A zero-length block is therefore
rejected at write time — permitting one would let it truncate iteration for everything after
it.

Checksums are XXH3, truncated to 32 bits.

## Reading

A read of an unknown record must first learn its length, which naively means two reads: one
for the header, one for the payload.

Instead the first read is speculative — it fetches a fixed 4 KB window, which covers the
header and, for most records, the entire payload. One read where the record fits, two where it
does not.

The window size is a deliberate trade rather than a maximum. Raising it would capture more
records in one read, but every read below the threshold then transfers bytes it does not use.
4 KB matches the page size and the default btree node size, so the common cases land inside it.

:::note[The cliff is real]
A record one byte past the window costs a second read for that byte. A btree node sized just
above 4 KB pays this on every access, which is why the node size and this window are chosen
together rather than independently.
:::

## Durability

Two sync modes, chosen per file by the layer above:

| Mode | Meaning |
| --- | --- |
| `BLOCK_MANAGER_SYNC_NONE` | Writes go to the page cache. Durable against process death, not machine death. |
| `BLOCK_MANAGER_SYNC_FULL` | Each write reaches the device before it is reported complete. |

Under `SYNC_FULL` the file is opened `O_DSYNC` where the platform has it, so the write syscall
itself carries the durability rather than a following `fdatasync`. Where it is unavailable the
manager falls back to an explicit `fdatasync` per write. The distinction matters for
performance, not semantics — both mean the bytes are on the device when the call returns.

Truncation is a special case: `ftruncate` is not covered by `O_DSYNC`, so a truncation always
syncs explicitly.

## Preallocation

An append that extends a file takes the kernel's per-inode write lock, so extending writes
serialize even when their offsets are disjoint. On a busy log this dominates.

The manager therefore extends the file's on-disk allocation ahead of the data, in chunks,
so that appends land **inside already-allocated space** and skip the extend path. When the
remaining reservation drops below a low-water mark, the next append extends again.

The chunk size is per-file rather than global. Small, short-lived files like the manifest disable
preallocation entirely, so that a copy of the file carries no trailing reserved zeros. Both the
direct path and the buffered ring extend the same way, the buffered one on the thread that reserved
the offset rather than on the flush thread that will write it.

The call underneath differs per platform — `fallocate` on Linux, `F_PREALLOCATE` followed by an
`ftruncate` on macOS, `FileAllocationInfo` then `FileEndOfFileInfo` on Windows, and
`posix_fallocate` elsewhere. macOS and Windows need that second step because reserving blocks does
not by itself advance the logical end of file, and it is the logical end that decides whether a
write is an extending one.

Whether `posix_fallocate` exists is **probed by the build**, not inferred from a feature-test macro.
`_POSIX_C_SOURCE` is something an application defines to request strict POSIX rather than something
a platform advertises, so testing it asks the wrong question and answers no on systems that have the
call — which silently removes preallocation from them entirely. OpenBSD genuinely lacks it and falls
through to the no-op.

### Giving the tail back

Preallocation advances the file's **logical end**, not just its block reservation, and that is
deliberate: reserving blocks while leaving `i_size` alone keeps the kernel treating every write as
an extending one, which buys nothing. The consequence is that a preallocated file is charged its
whole extent, not its data — and on a filesystem that reports allocated blocks, `du` and `df` agree.

So the extent has to be handed back when the file stops growing. There are two moments that can do
it, and only one of them is soon enough:

- **On close.** The manager trims to the data on the way out. That covers the write-ahead logs,
  which are closed once flushed.
- **When a build finishes.** An sstable is closed only when it is evicted or the database shuts
  down, so a live one holds its handle for as long as it is installed. Waiting for close would leave
  every installed sstable occupying a full chunk.

A finished sstable is therefore trimmed by its builder, before the durability barrier so the one
fsync covers the truncation as well. Skipping it is not a correctness bug and nothing fails — the
data is intact, reads are unaffected, and closing the database reclaims it all — which is exactly
what makes it easy to miss. What it does is make the store mostly padding: at a 64 MiB chunk, a
database of a few hundred sstables reports several gigabytes of live data while occupying tens of
gigabytes on disk, and the gap looks convincingly like a compaction that is failing to reclaim.

A platform where no variant is available is not broken, only slower: the first failure disables
further attempts for that file and writes take the extending path. Because that cost is large and
otherwise invisible, the first such failure in the process is logged once.

:::note[On ext4 this removes less than it appears to]
`fallocate` advances the logical end of file, which is what takes writes off the extending path.
It does not initialize the blocks — the extents come back marked unwritten, which is why the call
is cheap, and the first write into each one converts it. That conversion is itself a journalled
metadata operation. Preallocation therefore exchanges one metadata cost for another rather than
removing metadata work from the write path, and measured on ext4 it changes neither throughput nor
tail latency for the log. It still earns its place on filesystems that behave differently, and it
keeps the two write paths consistent.
:::

## The buffered append ring

This is the piece that makes concurrent commits scale, and it is the most intricate part of
the module. Its shape follows **Aether** (Johnson et al., PVLDB 2010) — see
[Design lineage](/internals/design-lineage).

The naive arrangement — every appender writes the file itself — puts every committing thread
on the same inode lock. Serializing a durable write is the single largest cost on the commit
path.

Instead:

```
   appender A ─┐                                    ┌─ flush thread
   appender B ─┼─> reserve offset (one fetch_add)   │   drains the contiguous
   appender C ─┘        │                           │   completed run and
                        v                           │   writes it in one call
              copy own bytes into the ring  ────────┘
                        │
              mark own slot complete
                        │
              wait for the frontier to pass it
```

1. **Reserve.** One atomic fetch-and-add on the file's size hands each appender a disjoint
   byte range. This is the only contended point, and it is a single instruction.
2. **Fill in parallel.** Each appender copies its framed record into its own slice of the
   ring. Appenders never wait for each other to copy.
3. **Release.** Each marks its slot complete.
4. **Drain in order.** One flush thread — the only thread that ever touches the file
   descriptor — advances over the **contiguous** run of completed records from the frontier
   and writes it out in a single call, then publishes the new frontier.
5. **Wait.** The appender returns once the frontier has passed its own record.

The properties this buys:

- **No inode-lock contention.** One writer, always.
- **Coalescing without a coordinator.** Records that arrive while a write is in flight are
  drained together in the next one; the batch size grows exactly when the writer is the
  bottleneck.
- **Gap-free output, guaranteed by construction.** Only the *contiguous* run is ever written,
  so a record can never reach the file before one that precedes it.

That last property is what [WAL replay](/internals/memtable-and-wal) depends on. Replay stops
at the first unreadable block, so a hole would discard everything after it.

The ring is bounded, so an appender whose slot still holds unflushed bytes waits for the
frontier to pass them. That is backpressure at the I/O layer: it bounds memory, and it is why
ring size is sized against the write buffer rather than made arbitrarily large.

A record larger than the whole ring cannot be staged — it would wrap onto itself. Such a
record waits to become the frontier, writes itself directly as a single vectored write, and
publishes the advanced frontier. Rare, and confined to oversized commit batches.

:::note[The flush thread backs off when there is nothing to write]
The park timeout is only a net for a wake that was somehow missed — `bm_wake_flush` is the real
signal, and it is ordered against the appender's completion flag so it cannot be lost. Holding a
short timeout while nothing arrives therefore buys nothing and costs a wakeup every half
millisecond, which on an otherwise idle database is most of the process's CPU. Consecutive empty
parks grow the timeout toward a quarter-second ceiling and any drained run resets it, so an idle
database costs nothing while a busy one still reacts on the signal rather than the timer.
:::

## Recovery

Opening an existing file validates the last block. A crash mid-append leaves a torn record,
and the two modes differ in what that means:

- **Permissive** truncates back to the last valid block. This is what a write-ahead log and
  the manifest want: the torn record was never acknowledged, so discarding it is correct and
  the file is usable again.
- **Strict** refuses. Reserved for cases where silent truncation would hide real damage.

A preallocated file needs this most: its on-disk size runs ahead of its data, so the tail is
reserved zeros. Without validation, a reopened preallocated file looks like it ends in a
record of size zero — which readers treat as end-of-file, correctly, but which leaves the
write cursor in the wrong place unless the real end is established at open.

## Invariants

| Invariant | Why |
| --- | --- |
| Only the contiguous completed run is written | Guarantees no gap; WAL replay would truncate at one |
| One thread writes a buffered file's descriptor | The ring's ordering guarantee assumes a single writer |
| A slot is not reusable until the frontier passes it | Otherwise a live record is overwritten before it is written out |
| Zero-length blocks are rejected at write | A zero size field reads as EOF and would truncate iteration |
| The trailing size must match the leading one | This is what makes a partial write detectable |
| `ftruncate` is synced explicitly | It is not covered by `O_DSYNC` |
| A file that has stopped growing is trimmed to its data | Preallocation advances the logical end, so an untrimmed file is charged its whole extent. An sstable cannot wait for close, since a live one never closes |
