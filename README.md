<div>
    <h1 align="left"><img width="68" src="artwork/tidesdb-logo-v8.png"></h1>
</div>

TidesDB is a fast and efficient transactional key value storage engine library written in C. The underlying data structure is based on a log-structured merge-tree (LSM-tree).

It is not a full-featured database, but rather a library that can be used to build a database atop of or used as a standalone key-value/column store.

[![Linux Build Status](https://github.com/tidesdb/tidesdb/actions/workflows/build_and_test_tidesdb.yml/badge.svg)](https://github.com/tidesdb/tidesdb/actions/workflows/build_and_test_tidesdb.yml)

## Features
- ACID with MVCC
- Column families
- Key-value seperation
- Hybrid LSM+BTree
- Lock-free internals
- Extensive transactional API (5 isolation levels), including 2PC-XA
- TTL
- Crash safe and durable
- Low space, and write amplification
- Cross-platform with file portability on Linux, macOS, Windows, BSD variants, Solaris/Illumos on x86, ARM, RISC-V, PowerPC (32-bit and 64-bit)


## Discord Community
Join the [TidesDB Discord Community](https://discord.gg/tWEmjR66cy) to ask questions, work on development, and discuss the future of TidesDB.

## License
Multiple licenses apply to TidesDB. The primary license is Mozilla Public License Version 2.0 (TidesDB), while additional licenses apply to the dependencies used in the project.

```
Mozilla Public License Version 2.0 (TidesDB)

== AND ==
BSD 2 (xxHash - Yann Collet)

== (optionally) ==
BSD 3 Clause (Snappy)
BSD 2 (LZ4)
BSD (Zstandard)
```