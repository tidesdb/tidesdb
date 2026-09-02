---
title: Preface
description: What TidesDB is, what it is not, who this manual is for, and the conventions it uses.
slug: preface
part: preface
sidebar:
  order: 1
---

# Preface

TidesDB is a transactional key-value storage engine written in C. It is a **library**, linked
into your process, storing data in a directory you name.

## What it is not

Being clear about this early saves time:

- **Not a database server.** There is no daemon, no port, no wire protocol, no authentication.
- **Not a query engine.** There is no SQL, no query planner, no secondary indexes. You get keys,
  values, ordered iteration, and transactions.
- **Not distributed.** No replication, no consensus, no sharding.

It is the layer such systems are built *on*. If you are building a database, a message queue, a
metadata store, or a storage layer for an application, TidesDB is intended to be the part that
makes bytes durable and gets them back in order.

## What it is

- **Transactional**, with five isolation levels from read-uncommitted to serializable, and
  two-phase commit for participating in distributed transactions.
- **Multi-version**, so readers never block writers and writers never block readers.
- **Crash-safe**, with a write-ahead log and a recovery path exercised on every open rather than
  only after a crash.
- **Log-structured**, optimised for write throughput, with compaction keeping read cost bounded.
- **Portable**, across Linux, macOS, Windows, the BSDs, and Illumos, on x86, ARM, RISC-V, and
  PowerPC.

## Who this manual is for

**If you are embedding TidesDB**, read [Getting Started](/getting-started), then
[Concepts](/concepts/data-model), then keep the [C API Reference](/reference/database) open.

**If you are operating something built on it**, [Administration](/administration/building) covers
building, configuration, operations, and monitoring.

**If you are modifying the engine**, [Internals](/internals/architecture) is written for you.
Start with the two narrative chapters — the life of a write and the life of a read — before any
subsystem chapter, and read [Invariants](/internals/invariants) before changing anything.

## Conventions

**Error sets are exhaustive.** Where the reference lists the errors a function returns, that list
is what the implementation actually produces, verified against the code rather than transcribed
from a header comment. "Or an error code" is not a contract and does not appear.

**Ownership is always stated.** A pointer you receive is either *borrowed* — owned by the engine,
valid for a stated period, never freed by you — or *owned*, in which case the reference says what
frees it. Memory the engine allocated is released with `tidesdb_free`, never your own `free`.

**One threading model covers the whole API**: a database handle and a column family handle are
shared freely across threads, while a transaction or an iterator belongs to one thread at a time —
neither carries a lock of its own, so concurrent calls on one of them are undefined rather than
serialized. Where a function departs from that, it says so. Two do: `tidesdb_close` requires that
no other thread is inside a call on the handle, and `tidesdb_txn_request_abort` may be called on a
transaction another thread is running, because it stores a flag and leaves that thread to act on
it.

**Every code sample in this manual is compiled** against the real public header as part of the
build. A sample that drifts from the API breaks the build rather than misleading you.

## Versions

This manual describes the release it ships with. The version is in `CMakeLists.txt` and
`vcpkg.json`; the documentation for a release is the documentation in that release's tree.

Compatibility policy — what a major, minor, and patch release may change, and what the on-disk
format guarantees — is in `VERSIONING.md`.

## A note on the writing

Chapters explain *why* before *what*, because a rule you understand is one you can apply to a
case the manual did not anticipate. Where a design decision has a cost, the cost is stated; where
something is a known weakness, it says so. A manual that only lists strengths is an advertisement,
and you cannot operate a system from an advertisement.
