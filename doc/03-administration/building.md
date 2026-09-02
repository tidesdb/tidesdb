---
title: Building and Installing
description: Compiling TidesDB from source, the build options, platform prerequisites, and verifying the result.
slug: administration/building
part: administration
sidebar:
  order: 1
---

# Building and Installing

TidesDB is a CMake project with no mandatory external dependencies. The compression backends
are optional and default on where a package exists; turn all three off and the library builds
against nothing but the C standard library and the platform's threads.

## Requirements

- **CMake** 3.25 or newer
- A **C11** compiler with atomics
- A threads implementation (pthreads, or the Win32 equivalent)

| Compiler | Minimum | Notes |
| --- | --- | --- |
| GCC | 7.0 | Linux, MinGW, cross-compilation |
| Clang | 6.0 | macOS, Linux, BSD |
| MSVC | 2019 16.8 | Requires `/experimental:c11atomics` |

## Quick build

```sh
cmake -S . -B build
cmake --build build -j
ctest --test-dir build
```

That gives you a build with tests, the default compression backends, and the platform's
default library type. `cmake --install build` installs it.

## Build options

Every option below is set with `-DNAME=VALUE` at configure time.

### What gets built

| Option | Default | Effect |
| --- | --- | --- |
| `TIDESDB_BUILD_TESTS` | `ON` | Unit and integration tests, plus the manual's sample-compile check |
| `TIDESDB_BUILD_FUZZERS` | `OFF` | Model-based differential, crash/recovery, and concurrency fuzz harnesses |
| `TIDESDB_BUILD_BENCH` | `OFF` | The `tidesdb_bench` driver — see [Testing and tools](/internals/testing-and-tools) |
| `BUILD_SHARED_LIBS` | Platform | Shared everywhere except Windows, which defaults to static to avoid DLL export complexity |

Everything is built position-independent, so a static archive still links into a shared
module without a rebuild.

### Compression backends

| Option | Default | Notes |
| --- | --- | --- |
| `TIDESDB_WITH_SNAPPY` | `ON`, `OFF` on SunOS | No OmniOS/Illumos package exists; still overridable |
| `TIDESDB_WITH_LZ4` | `ON` | |
| `TIDESDB_WITH_ZSTD` | `ON` | |

A build with all three off has no compression dependencies and supports
`TDB_COMPRESS_NONE` only. Which backends were compiled in is visible to consumers as
`TIDESDB_HAVE_SNAPPY`, `TIDESDB_HAVE_LZ4`, and `TIDESDB_HAVE_ZSTD` in
`<tidesdb/tidesdb_version.h>`.

If you vendor a compression library under a target name the auto-probe cannot guess — via
`FetchContent` or `add_subdirectory` — name it explicitly:

```sh
cmake -S . -B build -DTIDESDB_ZSTD_TARGET=zstd::libzstd_static
```

`TIDESDB_SNAPPY_TARGET` and `TIDESDB_LZ4_TARGET` work the same way. Empty (the default)
means probe the known target names, then fall back to `-l<name>`.

### Allocators

| Option | Default |
| --- | --- |
| `TIDESDB_WITH_MIMALLOC` | `OFF` |
| `TIDESDB_WITH_TCMALLOC` | `OFF` |
| `TIDESDB_WITH_JEMALLOC` | `OFF` |

These are mutually exclusive in practice — pick at most one. Enabling mimalloc also enables
the corresponding vcpkg feature.

:::caution[Allocator choice is part of your ABI]
Buffers returned by TidesDB must be released with
[`tidesdb_free`](/reference/database#tidesdb_free), never your own `free`. That is true
always, but building against a non-default allocator is what turns "should" into "will
crash".
:::

### Development builds

| Option | Default | Effect |
| --- | --- | --- |
| `TIDESDB_WITH_SANITIZER` | `OFF` | Address + undefined sanitizer |
| `TIDESDB_WITH_TSAN` | `OFF` | Thread sanitizer |
| `TIDESDB_WARN_STRICT` | `ON` | The extended warning set on the library target |
| `TIDESDB_WARN_MAYBE_UNINIT` | `OFF` | `-Wmaybe-uninitialized`; GCC only, needs an optimized build |
| `TIDESDB_WITH_ALLOC_FAULT` | `OFF` | Refuse a chosen allocation, for walking the out-of-memory paths |

`TIDESDB_WITH_SANITIZER` and `TIDESDB_WITH_TSAN` cannot be combined — the two runtimes are
incompatible and CMake rejects the combination rather than producing a broken build.

`TIDESDB_WITH_ALLOC_FAULT` redirects the library's allocations so a chosen one can be refused, which
needs a linker that can rewrite a symbol — GNU `ld` and `lld` through `--wrap`. CMake fails the
configure on toolchains that cannot, rather than building something that silently never fires. It
adds `alloc_fault_tests`, which measures how many allocations a small workload makes and then runs
it once per allocation, refusing a different one each time and requiring that the database still
opens and still owes back every commit it acknowledged. Pair it with the address sanitizer, where a
partial structure abandoned on the way out fails the round instead of passing quietly:

```sh
cmake -S . -B build-allocfault -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DTIDESDB_WITH_ALLOC_FAULT=ON -DTIDESDB_WITH_SANITIZER=ON
cmake --build build-allocfault -j && ./build-allocfault/alloc_fault_tests
```

## Installing dependencies

Only needed for the compression backends you leave enabled.

### Linux

```sh
# Debian/Ubuntu
sudo apt install cmake build-essential libsnappy-dev liblz4-dev libzstd-dev

# Fedora/RHEL/CentOS
sudo dnf install cmake gcc snappy-devel lz4-devel libzstd-devel

# Arch
sudo pacman -S cmake gcc snappy lz4 zstd
```

### macOS

Homebrew is auto-detected — `/opt/homebrew` on Apple Silicon, `/usr/local` on Intel — and only used
when a `brew` binary is actually there. MacPorts, pkgsrc, and Fink work by naming their prefix with
`MACOS_DEPENDENCY_PREFIX`, which takes precedence over Homebrew detection:

```sh
brew install cmake snappy lz4 zstd
cmake -S . -B build

# MacPorts
cmake -S . -B build -DMACOS_DEPENDENCY_PREFIX=/opt/local
```

| Option | Default | Effect |
| --- | --- | --- |
| `USE_HOMEBREW` | `ON` | Auto-detect Homebrew paths. `OFF` to keep them off the include and link lines entirely |
| `MACOS_DEPENDENCY_PREFIX` | unset | A custom dependency prefix; when set, Homebrew detection is skipped |

### Windows

```sh
vcpkg install snappy lz4 zstd
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake
```

The repository ships a `vcpkg.json` manifest, so a manifest-mode build resolves the
dependencies itself.

### BSD and Illumos

FreeBSD, OpenBSD, and DragonFlyBSD keep packages in `/usr/local`; NetBSD uses `/usr/pkg`.

```sh
# FreeBSD / OpenBSD / DragonFlyBSD
cmake -S . -B build -DCMAKE_PREFIX_PATH=/usr/local

# NetBSD
cmake -S . -B build -DCMAKE_PREFIX_PATH=/usr/pkg
```

On Illumos/OmniOS/Solaris, Snappy is off by default because no package exists.

## Supported platforms

| Operating system | Architectures |
| --- | --- |
| Linux | x86, x64, ARM64, PowerPC 32-bit, RISC-V 64-bit |
| macOS | x64, ARM64 (Apple Silicon) |
| Windows | x86, x64 (MSVC and MinGW) |
| FreeBSD 14.0+ | x64 |
| OpenBSD 7.4+ | x64 |
| NetBSD | x64 |
| DragonFlyBSD | x64 |
| Illumos/OmniOS, Solaris | x64 |

:::note[Platform notes]
- **PowerPC and 32-bit targets** need `libatomic` for 64-bit atomics, and multilib for 32-bit.
- **SunOS/Illumos** has no Snappy package, so that backend defaults off.
- **MSVC** needs `/experimental:c11atomics`, which the build adds for you.
:::

## Using TidesDB from your project

### With CMake

The install exports a package, so a consumer needs three lines:

```cmake
find_package(TidesDB REQUIRED)
add_executable(myapp main.c)
target_link_libraries(myapp PRIVATE TidesDB::tidesdb)
```

Linking `TidesDB::tidesdb` brings the include directory with it, so `<tidesdb/db.h>`
resolves without any `include_directories` of your own. If TidesDB is installed somewhere
unusual, point CMake at it with `-DCMAKE_PREFIX_PATH=/your/prefix`.

### Without CMake

```sh
cc main.c -ltidesdb -o myapp
```

The install ships three headers and nothing else: `<tidesdb/db.h>`, the generated
`<tidesdb/tidesdb_version.h>` (which carries `TIDESDB_VERSION` and the `TIDESDB_HAVE_*` codec
defines), and `<tidesdb/xxhash.h>`. `db.h` is self-contained — it includes nothing else from the
package — so a stale installation of an older TidesDB in the same prefix sits beside it
harmlessly.

The engine's internal headers are deliberately not installed. Nothing outside the library is
meant to reach them, and shipping them would make every one of them public API under the rule in
`VERSIONING.md`.

```c
#include <tidesdb/db.h>
```

## Verifying your build

Building is not the same as working. The project ships several checks, and running them is
how you know an unusual platform or an unusual option combination actually produced a sound
library.

### The test suite

```sh
cmake -S . -B build -DTIDESDB_BUILD_TESTS=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

This includes `doc_samples`, which compiles every C sample in this manual against the real
public header. A sample that drifts from the API it documents fails the build rather than
misleading you.

### Under the sanitizers

Worth doing on any platform not in the supported table above, and after any change to the
concurrency-sensitive paths.

```sh
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=RelWithDebInfo -DTIDESDB_WITH_SANITIZER=ON
cmake --build build-asan -j && ctest --test-dir build-asan

cmake -S . -B build-tsan -DCMAKE_BUILD_TYPE=RelWithDebInfo -DTIDESDB_WITH_TSAN=ON
cmake --build build-tsan -j && ctest --test-dir build-tsan
```

### The fuzzers

The strongest check, and the one that exercises durability. The crash harness forks a child
that commits under a sync barrier, kills it, reopens the database, and verifies the recovered
state is an exact prefix of what was acknowledged.

```sh
cmake -S . -B build-fuzz -DCMAKE_BUILD_TYPE=RelWithDebInfo -DTIDESDB_BUILD_FUZZERS=ON
cmake --build build-fuzz -j

TIDESDB_FUZZ_ITERS=100 ./build-fuzz/fuzz_standalone   # logical model
TIDESDB_FUZZ_ITERS=100 ./build-fuzz/fuzz_crash        # crash and recovery
TIDESDB_FUZZ_ITERS=50  ./build-fuzz/fuzz_conc         # concurrency
TIDESDB_FUZZ_ITERS=100 ./build-fuzz/fuzz_decode       # decoders, on untrusted bytes
```

What each one verifies, and how to reproduce a failure from its seed, is in
[Testing and tools](/internals/testing-and-tools).

`TIDESDB_FUZZ_DIR` picks where they work; point it at fast local storage, since each
iteration creates and tears down a database.

:::caution[Put fuzz and benchmark data on fast storage]
Per-iteration database teardown is dominated by filesystem work. On spinning disks these
harnesses run more than ten times slower, which reads as a hang rather than a slow run.
:::

## Troubleshooting

**`find_package(TidesDB)` cannot find the package.** Pass the install prefix:
`-DCMAKE_PREFIX_PATH=/your/prefix`. The package files land in
`<prefix>/lib/cmake/tidesdb`.

**Undefined references to atomic builtins.** Link `libatomic`. This affects 32-bit targets
and PowerPC, where 64-bit atomics are not native.

**A compression library is installed but not found.** The auto-probe looks for known target
and library names. Name yours explicitly with `-DTIDESDB_ZSTD_TARGET=...` (or the Snappy or
LZ4 equivalent), or drop the backend with `-DTIDESDB_WITH_ZSTD=OFF`.

**Sanitizer build fails to configure.** `TIDESDB_WITH_SANITIZER` and `TIDESDB_WITH_TSAN` are
mutually exclusive. Use two build directories.

**Crashes at the first free of a returned buffer.** The buffer was released with the wrong
`free`. Use [`tidesdb_free`](/reference/database#tidesdb_free) for anything TidesDB
allocated on your behalf.
