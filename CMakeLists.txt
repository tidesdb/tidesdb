cmake_minimum_required(VERSION 3.25)

option(TIDESDB_WITH_MIMALLOC "Use mimalloc as the memory allocator" OFF)
option(TIDESDB_WITH_TCMALLOC "Use tcmalloc as the memory allocator" OFF)
option(TIDESDB_WITH_JEMALLOC "Use jemalloc as the memory allocator" OFF)

# enable vcpkg mimalloc feature when TIDESDB_WITH_MIMALLOC is ON
# this must be set before project() for vcpkg to pick it up
if(TIDESDB_WITH_MIMALLOC)
    list(APPEND VCPKG_MANIFEST_FEATURES "mimalloc")
endif()

project(tidesdb
	VERSION 10.0.0
	LANGUAGES C)

set(CMAKE_C_STANDARD 11)

# build everything position-independent so the static archive (BUILD_SHARED_LIBS=OFF)
# can still link into a shared module like the mariadb plugin without recompile-with-fPIC errors
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# a production release build leaves warnings and sanitizers off; these opt into them for development
option(TIDESDB_WITH_SANITIZER "build with address+undefined sanitizer in tidesdb" OFF)
option(TIDESDB_WITH_TSAN "build with thread sanitizer in tidesdb (mutually exclusive with TIDESDB_WITH_SANITIZER)" OFF)
option(TIDESDB_BUILD_TESTS "enable building tests in tidesdb" ON)
option(TIDESDB_BUILD_FUZZERS "build the model-based fuzz harnesses (libFuzzer under Clang, plus a standalone/ci runner)" OFF)
option(TIDESDB_BUILD_BENCH "build the tidesdb_bench benchmark driver" OFF)
option(TIDESDB_WITH_ALLOC_FAULT "fail the nth allocation, for exercising out-of-memory unwind paths (needs GNU ld or lld)" OFF)

# compression backends -- optional, default ON. drop any with -DTIDESDB_WITH_<X>=OFF; a build with
# all three off has no compression dependencies and supports TDB_COMPRESS_NONE only.
# Snappy has no OmniOS/Illumos package, so its default is OFF on SunOS (still overridable with
# -DTIDESDB_WITH_SNAPPY=ON). the platform default must be chosen here, before option() creates the
# cache entry -- option() always seeds the variable, so a post-option "is it set?" test cannot tell
# a user override from the default and would never disable Snappy on SunOS.
if(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
    set(TIDESDB_SNAPPY_DEFAULT OFF)
else()
    set(TIDESDB_SNAPPY_DEFAULT ON)
endif()
option(TIDESDB_WITH_SNAPPY "build with Snappy compression support" ${TIDESDB_SNAPPY_DEFAULT})
option(TIDESDB_WITH_LZ4 "build with LZ4 compression support" ON)
option(TIDESDB_WITH_ZSTD "build with Zstd compression support" ON)

# explicit link override per backend, for consumers who vendor a compression lib (FetchContent /
# add_subdirectory) under a target name the auto-probe cannot guess. set to a CMake target or a raw
# link item, e.g. -DTIDESDB_ZSTD_TARGET=zstd::libzstd_static or -DTIDESDB_ZSTD_TARGET=zstd-neon.
# empty (default) = probe known target names, then fall back to -l<name>. 
set(TIDESDB_SNAPPY_TARGET "" CACHE STRING "external Snappy link target/item (empty = autodetect)")
set(TIDESDB_LZ4_TARGET "" CACHE STRING "external LZ4 link target/item (empty = autodetect)")
set(TIDESDB_ZSTD_TARGET "" CACHE STRING "external Zstd link target/item (empty = autodetect)")


# mirror the compression options into TIDESDB_HAVE_* for configure_file (consumer-visible defines)
if(TIDESDB_WITH_SNAPPY)
    set(TIDESDB_HAVE_SNAPPY ON)
endif()
if(TIDESDB_WITH_LZ4)
    set(TIDESDB_HAVE_LZ4 ON)
endif()
if(TIDESDB_WITH_ZSTD)
    set(TIDESDB_HAVE_ZSTD ON)
endif()

configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/src/tidesdb_version.h.in"
        "${CMAKE_CURRENT_BINARY_DIR}/tidesdb_version.h"
)
# BUILD_SHARED_LIBS controls static vs shared library
# Default to STATIC on Windows (avoids DLL export/import complexity), SHARED elsewhere
# Windows users can override with -DBUILD_SHARED_LIBS=ON if needed, but may require
# additional symbol export configuration for proper DLL builds
if(NOT DEFINED BUILD_SHARED_LIBS)
    if(WIN32)
        set(BUILD_SHARED_LIBS OFF)
    else()
        set(BUILD_SHARED_LIBS ON)
    endif()
endif()

if(MINGW)
    add_compile_definitions(__USE_MINGW_ANSI_STDIO=1)
endif()

# expose glibc extensions on linux (fallocate, etc.) for compat.h helpers
if(UNIX AND NOT APPLE)
    add_compile_definitions(_GNU_SOURCE)
endif()

# whether this platform actually provides posix_fallocate, which is what tdb_preallocate_extent
# falls back to away from linux, macos and windows. it must be probed rather than inferred from a
# feature-test macro: _POSIX_C_SOURCE is something an application defines to request strict posix,
# not something a platform advertises, so testing it asks the wrong question and answers no on the
# bsds and solaris -- which silently costs them preallocation entirely. openbsd has no
# posix_fallocate and correctly fails this probe.
include(CheckSymbolExists)
check_symbol_exists(posix_fallocate "fcntl.h" TIDESDB_HAS_POSIX_FALLOCATE)
if(TIDESDB_HAS_POSIX_FALLOCATE)
    add_compile_definitions(TIDESDB_HAVE_POSIX_FALLOCATE)
endif()

if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    if(NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 11.0)
        add_compile_options(-Wno-psabi)
    endif()
endif()

# optional -Wmaybe-uninitialized for development. GCC only (the flag is GCC-specific), and it is a
# no-op at -O0 because the analysis runs only under optimization, so pair it with an optimized
# build, e.g. -DTIDESDB_WARN_MAYBE_UNINIT=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo.
option(TIDESDB_WARN_MAYBE_UNINIT "enable -Wmaybe-uninitialized (GCC; requires an optimized build)" OFF)
if(TIDESDB_WARN_MAYBE_UNINIT AND CMAKE_C_COMPILER_ID STREQUAL "GNU")
    add_compile_options(-Wmaybe-uninitialized)
endif()

# development builds enable all warnings and, optionally, one sanitizer runtime
if(TIDESDB_WITH_SANITIZER AND TIDESDB_WITH_TSAN)
    message(FATAL_ERROR "TIDESDB_WITH_SANITIZER (ASan) and TIDESDB_WITH_TSAN cannot be combined -- the two runtimes are incompatible")
endif()

if(TIDESDB_WITH_TSAN)
    if(MSVC OR MINGW)
        message(FATAL_ERROR "ThreadSanitizer is not available on Windows toolchains")
    elseif(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD" OR CMAKE_SYSTEM_NAME STREQUAL "DragonFly" OR CMAKE_SYSTEM_NAME STREQUAL "SunOS" OR CMAKE_SYSTEM_NAME STREQUAL "NetBSD")
        message(FATAL_ERROR "ThreadSanitizer is not supported on this platform")
    else()
        # linux, macos, freebsd support TSan
        add_compile_options(-Wextra -Wall -fsanitize=thread -fno-omit-frame-pointer)
        add_link_options(-fsanitize=thread)
    endif()
elseif(TIDESDB_WITH_SANITIZER)
    if(MSVC)
        # debug flags for MSVC
        # MSVC ASAN can be unstable, so this branch enables only warnings for CI
        # suppress noisy warnings 4311 (pointer truncation), 4244 (conversion), 4047 (pointer indirection)
        # 4267 (size_t to smaller type conversion), 4127 (constant expression in conditional),
        # 4305 (type truncation),
        # 4702 (unreachable code)
        add_compile_options(/W4 /std:c17 /experimental:c11atomics /wd4311 /wd4244 /wd4267 /wd4047 /wd4189 /wd4101 /wd4459 /wd4127 /wd4305 /wd4702)
    elseif(MINGW)
        add_compile_options(-Wextra -Wall -std=c11)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD" OR CMAKE_SYSTEM_NAME STREQUAL "DragonFly" OR CMAKE_SYSTEM_NAME STREQUAL "SunOS" OR CMAKE_SYSTEM_NAME STREQUAL "NetBSD")
        # ASan is unavailable on OpenBSD, DragonFlyBSD and OmniOS/Illumos, and on NetBSD it does not
        # sit with the ASLR the kernel applies -- the instrumented binary exits before running a
        # single test, so the suite passes by not running. warnings stay on, the sanitizer does not,
        # and the refusal lives here rather than in each caller's configure line.
        #
        # said out loud, because a caller that asked for a sanitizer and quietly did not get one is
        # the same green-without-running failure by another route
        message(STATUS "tidesdb: ${CMAKE_SYSTEM_NAME} cannot run the address sanitizer, building without it")
        add_compile_options(-Wextra -Wall)
    elseif(CMAKE_SYSTEM_NAME MATCHES "BSD")
        # FreeBSD and the remaining BSDs run the sanitizers
        add_compile_options(-Wextra -Wall -fsanitize=address,undefined)
        add_link_options(-fsanitize=address,undefined)
    else()
        add_compile_options(-Wextra -Wall -fsanitize=address,undefined)
        add_link_options(-fsanitize=address,undefined)
    endif()
else()
    if(MSVC)
        # ensure C17 support and C11 atomics are enabled even without sanitizers
        # disable only genuine test-noise warnings that clutter output:
        # 4189: local variable initialized but not referenced
        # 4101: unreferenced local variable
        # 4459: declaration hides global declaration
        # 4702: unreachable code
        # 4700 (uninitialized local used) and 4013 (implicit function declaration) are left
        # enabled -- both flag real bugs and must not be silenced
        add_compile_options(/std:c17 /experimental:c11atomics /wd4189 /wd4101 /wd4459 /wd4702)
    elseif(MINGW)
        add_compile_options(-Wextra -Wall -std=c11)
    else()
        # Unix/Linux/macOS/BSD with GCC or Clang -- warnings belong on the default build, not only
        # under the sanitizer, so dead code and uninitialized use surface without a sanitizer run
        add_compile_options(-Wextra -Wall)
    endif()
endif()

# vendored third-party headers, added as SYSTEM so their diagnostics never mix into this project's
# warning output -- the code here is upstream's to change, not ours
include_directories(SYSTEM external)

# create library (respects BUILD_SHARED_LIBS option)
# note on windows, STATIC is recommended to avoid DLL export/import complexity
# users can override with -DBUILD_SHARED_LIBS=ON/OFF
set(TIDESDB_SOURCES
    src/db.c src/engine/engine.c src/engine/engine_l0.c src/engine/engine_recovery.c src/engine/engine_txn.c src/engine/engine_compaction.c src/engine/engine_reaper.c src/engine/engine_iter.c src/engine/engine_stats.c src/engine/engine_ops.c src/engine/engine_backup.c src/engine/engine_cf_ops.c src/engine/engine_prepared.c src/io/block_manager_core.c src/io/block_manager_util.c src/io/block_manager_write.c src/io/block_manager_cursor.c src/io/block_manager_recover.c src/io/block_manager_fault.c src/base/alloc_fault.c src/datastructures/skip_list/skip_list_node.c src/datastructures/skip_list/skip_list_core.c src/datastructures/skip_list/skip_list_read.c src/datastructures/skip_list/skip_list_cursor.c src/datastructures/skip_list/skip_list_write.c src/base/encoding/compress.c src/sstable/bloom_filter.c
    src/sstable/pr_filter.c
    src/manifest/manifest_set.c src/manifest/manifest_record.c src/manifest/manifest_log.c src/manifest/manifest_api.c src/column_family/cf_config.c src/column_family/column_family.c src/column_family/cf_registry.c src/column_family/cf_iter.c src/flush/flush.c src/compaction/compaction_exec.c src/compaction/compaction_planner.c src/iter/merge_iter.c src/iter/merge_sources.c src/column_family/level/level_set.c src/fdmanager/fdmanager.c src/fdmanager/reaper.c src/datastructures/queue.c src/range_tombstone/range_tombstone.c src/sstable/btree/btree_node.c src/sstable/btree/btree_node_encode.c src/sstable/btree/btree_builder.c src/sstable/btree/btree_read.c src/sstable/btree/btree_cursor.c
    src/sstable/vlog.c src/sstable/vlog_reclaim.c src/sstable/vlog_segment.c src/sstable/sstable.c
    src/sstable/sstable_footer.c
    src/sstable/sstable_read.c src/sstable/sstable_builder.c
    src/base/log.c src/base/errors.c src/base/encoding/encoding.c src/base/lockfree.c src/base/arena.c src/cache/cache.c src/base/bg_pool.c src/base/bg_ticker.c src/threadmanager/threadmanager.c src/memtable/memtable.c src/memtable/l0_read.c src/memtable/backpressure.c src/memtable/l0_admission.c src/txn/mvcc.c src/txn/wal_record.c src/txn/source.c src/txn/writeset.c src/txn/readset.c src/txn/registry.c src/txn/txn.c src/txn/txn_commit.c src/txn/txn_two_phase.c src/txn/l0_adapter.c src/txn/cf_source.c src/txn/prepare_stage.c
    external/xxhash.c)

# vendored sources are compiled as-is; their diagnostics belong upstream, and letting them into this
# build's output would train everyone to ignore it
if(MSVC)
    set_source_files_properties(external/xxhash.c PROPERTIES COMPILE_OPTIONS "/w")
else()
    set_source_files_properties(external/xxhash.c PROPERTIES COMPILE_OPTIONS "-w")
endif()

add_library(tidesdb ${TIDESDB_SOURCES})

set_target_properties(tidesdb PROPERTIES
	                      VERSION "${PROJECT_VERSION}"
                              SOVERSION "${PROJECT_VERSION_MAJOR}")

target_include_directories(tidesdb PRIVATE src)

# the test and fuzz sources declare their cases as bare
# test_x(), which trips the prototype and shadow flags in bulk without indicating a defect there.
# each flag is probed before use so an older GCC, a Clang, or a BSD toolchain that lacks one still
# configures. -Wswitch-enum is deliberately absent: the compression backends are selected by
# #ifdef, so a build with a backend disabled removes its case labels and the flag then fires on
# switches that are already correct via their default arm.
option(TIDESDB_WARN_STRICT "compile the library with the extended warning set" ON)
if(TIDESDB_WARN_STRICT AND (CMAKE_C_COMPILER_ID STREQUAL "GNU" OR CMAKE_C_COMPILER_ID MATCHES "Clang"))
    include(CheckCCompilerFlag)
    set(TIDESDB_STRICT_WARNINGS
        -Wshadow
        -Wcast-align
        -Wpointer-arith
        -Wwrite-strings
        -Wredundant-decls
        -Wstrict-prototypes
        -Wmissing-prototypes
        -Wold-style-definition
        -Wdouble-promotion
        -Wformat=2
        -Wundef
        -Wvla
    )
    foreach(warn_flag IN LISTS TIDESDB_STRICT_WARNINGS)
        string(REGEX REPLACE "[^A-Za-z0-9]" "_" warn_var "HAVE_WARN${warn_flag}")
        check_c_compiler_flag(${warn_flag} ${warn_var})
        if(${warn_var})
            target_compile_options(tidesdb PRIVATE ${warn_flag})
        endif()
    endforeach()
endif()

# deterministic write-fault injection for crash-recovery tests and fuzzers; compiled out of a plain
# production build so the hot write path pays nothing. PUBLIC so a test can call the arm/disarm api
if(TIDESDB_BUILD_TESTS OR TIDESDB_BUILD_FUZZERS)
    target_compile_definitions(tidesdb PUBLIC TDB_FAULT_INJECTION)
endif()

# deterministic allocation-failure injection, for walking the out-of-memory unwind paths. it needs
# the linker to redirect malloc/calloc/realloc, which GNU ld and lld do through --wrap and other
# linkers do not, so it stays an explicit developer build rather than riding along with the tests.
# PUBLIC so a test binary is wrapped on the same terms the library is, and the count covers both
if(TIDESDB_WITH_ALLOC_FAULT)
    if(MSVC OR APPLE)
        message(FATAL_ERROR "TIDESDB_WITH_ALLOC_FAULT needs a --wrap-capable linker (GNU ld or lld)")
    endif()
    target_compile_definitions(tidesdb PUBLIC TDB_ALLOC_FAULT)
    target_link_options(tidesdb PUBLIC -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=realloc)
endif()

# the decoder fuzz target needs to hand bytes to the btree node decoder directly. on the real read
# path those bytes arrive from the block manager, which verifies a checksum over them first, so a
# fuzzer going through the file would only ever exercise the checksum and never the decoder. PUBLIC
# so the target sees the same declaration the library was built with
if(TIDESDB_BUILD_TESTS OR TIDESDB_BUILD_FUZZERS)
    target_compile_definitions(tidesdb PUBLIC TDB_TEST_INTERNALS)
endif()

# split the build and install views: an exported target must not carry this machine's source path.
# the build tree offers both include/ (so an in-tree consumer writes "db.h") and the assembled
# binary include/ (so it can also write <tidesdb/db.h>, matching what installs); the install tree
# offers the include root, under which the headers live in tidesdb/
include(GNUInstallDirs)
target_include_directories(tidesdb PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

# private build-time signal that drives the per-backend guards in compress.c
if(TIDESDB_WITH_SNAPPY)
    target_compile_definitions(tidesdb PRIVATE TIDESDB_HAVE_SNAPPY)
endif()
if(TIDESDB_WITH_LZ4)
    target_compile_definitions(tidesdb PRIVATE TIDESDB_HAVE_LZ4)
endif()
if(TIDESDB_WITH_ZSTD)
    target_compile_definitions(tidesdb PRIVATE TIDESDB_HAVE_ZSTD)
endif()

# link one compression backend, resolving its name in three steps so a vendored or system-provided
# library both work. resolution order:
#   1. an explicit override in TIDESDB_<X>_TARGET -- a CMake target or raw link item the consumer
#      passes in. this is the escape hatch for a dependency built under a non-standard target name
#      (e.g. a FetchContent build named zstd-neon-enabled) where name-probing cannot guess it.
#   2. a known CMake target already defined in the build (find_package / FetchContent /
#      add_subdirectory). linking the target carries its include dirs and the in-tree artifact,
#      which a bare -l<name> cannot
#   3. a bare -l<name> against a system/installed library (the historical fallback).
# used by every POSIX platform branch below so the behavior is uniform, not Linux-only.
function(_tidesdb_link_compression libname)
    string(TOUPPER ${libname} _up)
    if(TIDESDB_${_up}_TARGET)
        target_link_libraries(tidesdb PUBLIC ${TIDESDB_${_up}_TARGET})
        message(STATUS "tidesdb: linking ${libname} via TIDESDB_${_up}_TARGET=${TIDESDB_${_up}_TARGET}")
        return()
    endif()
    set(candidates "")
    if(libname STREQUAL "zstd")
        list(APPEND candidates
                zstd::libzstd_shared zstd::libzstd_static zstd::libzstd
                libzstd_shared libzstd_static libzstd zstd)
    elseif(libname STREQUAL "snappy")
        list(APPEND candidates Snappy::snappy snappy)
    elseif(libname STREQUAL "lz4")
        list(APPEND candidates lz4::lz4 LZ4::lz4 lz4)
    endif()
    foreach(tgt IN LISTS candidates)
        if(TARGET ${tgt})
            target_link_libraries(tidesdb PUBLIC ${tgt})
            message(STATUS "tidesdb: linking ${libname} via existing target ${tgt}")
            return()
        endif()
    endforeach()
    target_link_libraries(tidesdb PUBLIC -l${libname})
endfunction()

# link every compression backend enabled by the -DTIDESDB_WITH_* options through the resolver above
macro(_tidesdb_link_enabled_compression)
    if(TIDESDB_WITH_LZ4)
        _tidesdb_link_compression(lz4)
    endif()
    if(TIDESDB_WITH_ZSTD)
        _tidesdb_link_compression(zstd)
    endif()
    if(TIDESDB_WITH_SNAPPY)
        _tidesdb_link_compression(snappy)
    endif()
endmacro()

# link whichever alternative allocator is enabled; each override intercepts malloc/free globally when
# linked. the same block was repeated in every POSIX platform branch, so it lives once here
macro(_tidesdb_link_allocators)
    if(TIDESDB_WITH_MIMALLOC)
        target_link_libraries(tidesdb PUBLIC mimalloc)
    endif()
    if(TIDESDB_WITH_TCMALLOC)
        target_link_libraries(tidesdb PUBLIC ${TCMALLOC_LIBRARIES})
        target_include_directories(tidesdb PUBLIC ${TCMALLOC_INCLUDE_DIRS})
    endif()
    if(TIDESDB_WITH_JEMALLOC)
        target_link_libraries(tidesdb PUBLIC ${JEMALLOC_LIBRARIES})
        target_include_directories(tidesdb PUBLIC ${JEMALLOC_INCLUDE_DIRS})
    endif()
endmacro()

# find compression libraries.
# MSVC builds rely on vcpkg, which ships full CMake config packages.
# MinGW (MSYS2) zstd and lz4 ship only pkg-config (.pc) files, no CMake
# configs, so use PkgConfig for them. snappy is the opposite, upstream
# snappy installs SnappyConfig.cmake but no .pc (so the x86 from-source
# build in CI cannot use pkg-config), while MSYS2's prebuilt snappy ships
# both. CONFIG mode works for snappy across all three setups.
# winpthreads is bundled with the MinGW toolchain, so a plain pthread link resolves it.
if(WIN32)
    if(MINGW)
        find_package(PkgConfig REQUIRED)
        if(TIDESDB_WITH_ZSTD)
            pkg_check_modules(ZSTD REQUIRED IMPORTED_TARGET libzstd)
        endif()
        if(TIDESDB_WITH_LZ4)
            pkg_check_modules(LZ4 REQUIRED IMPORTED_TARGET liblz4)
        endif()
        if(TIDESDB_WITH_SNAPPY)
            find_package(Snappy CONFIG REQUIRED)
        endif()
    else()
        if(TIDESDB_WITH_ZSTD)
            find_package(zstd CONFIG REQUIRED)
        endif()
        if(TIDESDB_WITH_SNAPPY)
            find_package(Snappy CONFIG REQUIRED)
        endif()
        if(TIDESDB_WITH_LZ4)
            find_package(lz4 CONFIG REQUIRED)
        endif()
        # MSVC uses the native Win32 threading backend in compat.h, so no pthreads-win32 package
    endif()
endif()

# mimalloc support (optional, OFF by default)
# mimalloc provides automatic malloc/free override when linked
if(TIDESDB_WITH_MIMALLOC)
    if(WIN32)
        find_package(mimalloc CONFIG REQUIRED)
    else()
        find_package(mimalloc REQUIRED)
    endif()
    message(STATUS "Building with mimalloc memory allocator")
endif()

# tcmalloc support (optional, OFF by default)
# tcmalloc provides automatic malloc/free override when linked
if(TIDESDB_WITH_TCMALLOC)
    find_package(PkgConfig REQUIRED)
    # try full libtcmalloc first (Linux libgoogle-perftools-dev), then minimal (vcpkg)
    pkg_check_modules(TCMALLOC libtcmalloc)
    if(NOT TCMALLOC_FOUND)
        pkg_check_modules(TCMALLOC REQUIRED libtcmalloc_minimal)
    endif()
    message(STATUS "Building with tcmalloc memory allocator")
endif()

# jemalloc support (optional, OFF by default)
# jemalloc provides automatic malloc/free override when linked
if(TIDESDB_WITH_JEMALLOC)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(JEMALLOC REQUIRED jemalloc)
    message(STATUS "Building with jemalloc memory allocator")
endif()

if(APPLE)
    # macOS supports multiple package managers (Homebrew, MacPorts, pkgsrc, Fink, etc).
    # -DMACOS_DEPENDENCY_PREFIX=/path names a custom prefix, and -DUSE_HOMEBREW=ON/OFF controls
    # Homebrew detection (the default is ON)

    option(USE_HOMEBREW "Auto-detect and use Homebrew paths on macOS" ON)

    if(DEFINED MACOS_DEPENDENCY_PREFIX)
        # user explicitly specified a prefix (e.g., MacPorts /opt/local, pkgsrc /usr/pkg)
        message(STATUS "Using custom macOS dependency prefix: ${MACOS_DEPENDENCY_PREFIX}")
        target_include_directories(tidesdb PUBLIC ${MACOS_DEPENDENCY_PREFIX}/include)
        target_link_directories(tidesdb PUBLIC ${MACOS_DEPENDENCY_PREFIX}/lib)
    elseif(USE_HOMEBREW)
        if(CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64")
            # Apple Silicon -- Homebrew uses /opt/homebrew
            set(HOMEBREW_PREFIX "/opt/homebrew")
        else()
            # Intel Mac -- Homebrew uses /usr/local
            set(HOMEBREW_PREFIX "/usr/local")
        endif()

        if(EXISTS "${HOMEBREW_PREFIX}/bin/brew")
            message(STATUS "Detected Homebrew at ${HOMEBREW_PREFIX}")
            target_include_directories(tidesdb PUBLIC ${HOMEBREW_PREFIX}/include)
            target_link_directories(tidesdb PUBLIC ${HOMEBREW_PREFIX}/lib)
        else()
            message(WARNING "Homebrew not found at ${HOMEBREW_PREFIX}, relying on system paths. "
                    "If using MacPorts, pkgsrc, or Fink, specify -DMACOS_DEPENDENCY_PREFIX=/path or -DUSE_HOMEBREW=OFF")
        endif()
    else()
        message(STATUS "Using system default paths on macOS (USE_HOMEBREW=OFF)")
        # let CMake find packages in standard locations
        # or rely on CMAKE_PREFIX_PATH being set by the user
    endif()

    target_link_libraries(tidesdb PUBLIC
            m           # math library
            pthread     # pthread library
    )
    _tidesdb_link_enabled_compression()

    if(CMAKE_SIZEOF_VOID_P EQUAL 4)
        target_link_libraries(tidesdb PUBLIC atomic)
    endif()

    _tidesdb_link_allocators()

elseif(WIN32)
    # for windows, link against the enabled compression libraries and pthreads
    if(MINGW)
        if(TIDESDB_WITH_ZSTD)
            target_link_libraries(tidesdb PUBLIC PkgConfig::ZSTD)
        endif()
        if(TIDESDB_WITH_LZ4)
            target_link_libraries(tidesdb PUBLIC PkgConfig::LZ4)
        endif()
        if(TIDESDB_WITH_SNAPPY)
            target_link_libraries(tidesdb PUBLIC Snappy::snappy)
        endif()
        target_link_libraries(tidesdb PUBLIC pthread)
    else()
        if(TIDESDB_WITH_ZSTD)
            target_link_libraries(tidesdb PUBLIC
                    $<IF:$<TARGET_EXISTS:zstd::libzstd_shared>,zstd::libzstd_shared,zstd::libzstd_static>)
        endif()
        if(TIDESDB_WITH_SNAPPY)
            target_link_libraries(tidesdb PUBLIC Snappy::snappy)
        endif()
        if(TIDESDB_WITH_LZ4)
            target_link_libraries(tidesdb PUBLIC lz4::lz4)
        endif()
        # MSVC threading is the native Win32 backend in compat.h -- nothing to link
    endif()

    if(TIDESDB_WITH_MIMALLOC)
        target_link_libraries(tidesdb PUBLIC mimalloc)
    endif()

    # tcmalloc is not supported on Windows
    # jemalloc is not supported on Windows
elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD" OR CMAKE_SYSTEM_NAME STREQUAL "OpenBSD" OR
       CMAKE_SYSTEM_NAME STREQUAL "NetBSD" OR CMAKE_SYSTEM_NAME STREQUAL "DragonFly")
    # the BSDs share one link recipe and differ only in where packages install -- pkgsrc puts them
    # under /usr/pkg on NetBSD, the ports/pkg tree uses /usr/local on FreeBSD, OpenBSD, and DragonFly
    if(CMAKE_SYSTEM_NAME STREQUAL "NetBSD")
        set(TIDESDB_BSD_PREFIX /usr/pkg)
    else()
        set(TIDESDB_BSD_PREFIX /usr/local)
    endif()
    target_include_directories(tidesdb PUBLIC ${TIDESDB_BSD_PREFIX}/include)
    target_link_directories(tidesdb PUBLIC ${TIDESDB_BSD_PREFIX}/lib)
    target_link_libraries(tidesdb PUBLIC
            m           # math library
            pthread     # pthread library
    )
    _tidesdb_link_enabled_compression()
    _tidesdb_link_allocators()
elseif(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
    # OmniOS/Illumos -- OpenIndiana Community Edition packages in /opt/ooce
    # snappy is not packaged for OmniOS, so TIDESDB_WITH_SNAPPY defaults OFF here and the
    # compression list carries only the backends actually available (lz4/zstd by default)
    target_include_directories(tidesdb PUBLIC /opt/ooce/include /usr/include)
    target_link_directories(tidesdb PUBLIC /opt/ooce/lib/amd64 /usr/lib/amd64)
    target_link_libraries(tidesdb PUBLIC
            m           # math library
            pthread     # pthread library
    )
    _tidesdb_link_enabled_compression()
    _tidesdb_link_allocators()
else()
    # for linux and other unix systems -- resolve each enabled backend through the shared helper
    # (override -> known target -> -l fallback). the target probe matters because some distros
    # (e.g. Oracle Linux 8, RHEL 8) ship zstd-devel CMake configs that define zstd::libzstd as a
    # MODULE target and break find_package(zstd CONFIG) for plain linking, and a parent build doing
    # FetchContent / add_subdirectory provides the lib only as a target, never as a system -l.
    _tidesdb_link_enabled_compression()

    target_link_libraries(tidesdb PUBLIC
            pthread
            m           # math library
            atomic      # atomic operations library (required for 32-bit architectures like PowerPC)
    )

    # libstdc++ is only pulled in by Snappy's C++ implementation; skip it when Snappy is off so a
    # no-Snappy build does not acquire a C++ runtime dependency
    if(TIDESDB_WITH_SNAPPY)
        target_link_libraries(tidesdb PUBLIC stdc++)
    endif()

    _tidesdb_link_allocators()
endif()


include(GNUInstallDirs)
# the install set is exported as TidesDBTargets, which TidesDBConfig.cmake includes -- without the
# export a find_package(TidesDB) fails on the missing targets file rather than on anything the
# consumer did. the interface include directory is the parent of tidesdb/, so a consumer writes
# #include <tidesdb/db.h> against either the install tree or the build tree
install(TARGETS tidesdb
	EXPORT TidesDBTargets
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
	INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT TidesDBTargets
	FILE TidesDBTargets.cmake
	NAMESPACE TidesDB::
	DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/tidesdb")

# only the public surface is installed. installing the engine's own headers under src/ alongside it
# would make every internal header reachable, and a reachable header is public by the rule in
# VERSIONING.md whatever the intent. db.h is self-contained, so a consumer needs nothing else from
# src/
install(DIRECTORY include/ DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/tidesdb" FILES_MATCHING PATTERN "*.h")
install(FILES external/xxhash.h DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/tidesdb")
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/tidesdb_version.h" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/tidesdb")

# consolidate a single include directory in the build tree so a consumer can use
# -I<build_dir>/include and #include <tidesdb/db.h>
set(BUILD_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/include/tidesdb")
file(MAKE_DIRECTORY ${BUILD_INCLUDE_DIR})

# copy all headers to the build include directory. db.h is the public header from include/; the
# engine-internal headers under src/ (including the base/ subtree) come along so a consumer of the
# build tree can also reach them, mirroring the install layout
file(GLOB SRC_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.h")
file(GLOB PUB_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h")
file(GLOB BASE_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/src/base/*.h")
file(GLOB INTERNAL_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/src/internal/*.h")
file(GLOB EXT_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/external/*.h")
file(COPY ${SRC_HEADERS} DESTINATION ${BUILD_INCLUDE_DIR})
file(COPY ${PUB_HEADERS} DESTINATION ${BUILD_INCLUDE_DIR})
file(COPY ${EXT_HEADERS} DESTINATION ${BUILD_INCLUDE_DIR})
file(MAKE_DIRECTORY ${BUILD_INCLUDE_DIR}/base)
file(COPY ${BASE_HEADERS} DESTINATION ${BUILD_INCLUDE_DIR}/base)
file(MAKE_DIRECTORY ${BUILD_INCLUDE_DIR}/internal)
file(COPY ${INTERNAL_HEADERS} DESTINATION ${BUILD_INCLUDE_DIR}/internal)

# copy generated version header (done at build time since it's generated)
add_custom_command(TARGET tidesdb POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_CURRENT_BINARY_DIR}/tidesdb_version.h"
        "${BUILD_INCLUDE_DIR}/tidesdb_version.h"
        COMMENT "Copying tidesdb_version.h to build include directory"
)

if(TIDESDB_BUILD_TESTS) 
    enable_testing()

    # the manual's C samples, extracted into one translation unit and compiled against the real
    # public header. a sample that drifts from the api it documents is the failure mode docs have
    # that code does not -- the prose still reads plausibly -- so this turns it into a build error.
    # python is optional: without it the check is skipped rather than failing the build
    find_package(Python3 COMPONENTS Interpreter QUIET)
    if(Python3_Interpreter_FOUND)
        set(TIDESDB_DOC_SAMPLES_C ${CMAKE_CURRENT_BINARY_DIR}/doc_samples.c)
        file(GLOB_RECURSE TIDESDB_DOC_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/doc/*.md)
        add_custom_command(
            OUTPUT ${TIDESDB_DOC_SAMPLES_C}
            COMMAND ${Python3_EXECUTABLE}
                    ${CMAKE_CURRENT_SOURCE_DIR}/doc/tools/extract_doc_samples.py
                    ${CMAKE_CURRENT_SOURCE_DIR}/doc
                    ${TIDESDB_DOC_SAMPLES_C}
            DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/doc/tools/extract_doc_samples.py ${TIDESDB_DOC_SOURCES}
            COMMENT "extracting manual C samples")
        # the manual's samples include <tidesdb/db.h>, the way a consumer writes it after an
        # install. that spelling cannot resolve from include/, which holds a bare db.h, so without
        # a tidesdb/ directory of its own the compiler reaches past the source tree and validates
        # the manual against whatever copy is installed on the machine -- the one thing this gate
        # must never do, since a stale install makes drift compile clean. stage the real header at
        # build time, dependent on it, so the gate always reads the tree it ships with
        set(TIDESDB_DOC_INCLUDE ${CMAKE_CURRENT_BINARY_DIR}/doc_include)
        add_custom_command(
            OUTPUT ${TIDESDB_DOC_INCLUDE}/tidesdb/db.h
            COMMAND ${CMAKE_COMMAND} -E make_directory ${TIDESDB_DOC_INCLUDE}/tidesdb
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/db.h ${TIDESDB_DOC_INCLUDE}/tidesdb/db.h
            DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/include/db.h
            COMMENT "staging the public header for the manual samples")

        add_executable(doc_samples ${TIDESDB_DOC_SAMPLES_C} ${TIDESDB_DOC_INCLUDE}/tidesdb/db.h)
        target_include_directories(doc_samples BEFORE PRIVATE ${TIDESDB_DOC_INCLUDE})
        target_include_directories(doc_samples PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
        target_link_libraries(doc_samples PRIVATE tidesdb)
        # a sample declares only what it needs, so an unused local is the sample being readable
        # rather than a defect
        if(MSVC)
            # a call to something that no longer exists must fail, not warn -- that is the whole
            # point of compiling the samples
            target_compile_options(doc_samples PRIVATE /we4013)
        else()
            target_compile_options(doc_samples PRIVATE
                -Wno-unused-but-set-variable -Wno-unused-variable
                # a sample calling a function that no longer exists is only an implicit declaration
                # by default, which would let the exact drift this guards against pass as a warning
                -Werror=implicit-function-declaration
                -Werror=implicit-int
                -Werror=incompatible-pointer-types)
        endif()
        add_test(NAME doc_samples COMMAND doc_samples)
    endif()


    # one list drives the build, the link line and the ctest registration. spelling each target out
    # three times let the three copies drift apart silently, and a target missing from any one of
    # them is a test that is built but never linked, or built but never run
    set(TIDESDB_TESTS
        base_log_tests
        base_serialization_tests
        encoding_tests
        base_lockfree_tests
        cache_tests
        arena_tests
        bg_pool_tests
        bg_ticker_tests
        threadmanager_tests
        memtable_tests
        l0_adapter_tests
        cf_source_tests
        backpressure_tests
        mvcc_tests
        wal_record_tests
        source_tests
        writeset_tests
        readset_tests
        registry_tests
        txn_tests
        base_errors_tests
        block_manager_tests
        block_manager_cursor_tests
        skip_list_tests
        compress_tests
        bloom_filter_tests
        pr_filter_tests
        manifest_tests
        queue_tests
        range_tombstone_tests
        btree_tests
        vlog_tests
        sstable_tests
        level_set_tests
        fdmanager_tests
        cf_config_tests
        flush_tests
        merge_iter_tests
        merge_sources_tests
        cf_iter_tests
        compaction_exec_tests
        compaction_planner_tests
        compaction_pipeline_tests
        reaper_tests
        column_family_tests
        cf_registry_tests
        engine_tests
        ttl_tests
        txn_api_tests
        iter_api_tests
    )

    # the crash-recovery tests start a child from this same binary rather than forking, so they
    # build and run everywhere the rest of the suite does
    list(APPEND TIDESDB_TESTS crash_recovery_tests)

    # the allocation-failure sweep only means anything when the injector is linked in
    if(TIDESDB_WITH_ALLOC_FAULT)
        list(APPEND TIDESDB_TESTS alloc_fault_tests)
    endif()

    foreach(test_target IN LISTS TIDESDB_TESTS)
        # base_log_tests -> test/base_log__tests.c
        string(REGEX REPLACE "_tests$" "" test_stem ${test_target})
        add_executable(${test_target} test/${test_stem}__tests.c)
        target_link_libraries(${test_target} PRIVATE tidesdb)
        target_include_directories(${test_target} SYSTEM PRIVATE external)
        target_include_directories(${test_target} PRIVATE src)
        add_test(NAME ${test_target} COMMAND ${test_target})
        # the undefined-behaviour sanitizer prints and carries on by default, so a finding lands in
        # the middle of a passing run and is read as noise. told to stop, it fails the test that
        # provoked it and names it -- which is the only way one gets noticed
        set_tests_properties(${test_target} PROPERTIES ENVIRONMENT
                             "UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1:abort_on_error=1")
    endforeach()

    # the portability pair writes a database and reads it back, and is what the cross-platform CI
    # jobs run against an artifact produced on another architecture. they are built here rather than
    # embedded in the workflow so a public API change breaks the build instead of rotting unseen,
    # and they are deliberately denied the src include path so they prove db.h alone is enough
    foreach(portable_target portable_db_create portable_db_verify)
        add_executable(${portable_target} test/portability/${portable_target}.c)
        target_link_libraries(${portable_target} PRIVATE tidesdb)
    endforeach()

    # run the round trip locally too, so format drift is caught without waiting for a CI matrix.
    # create deliberately leaves the database behind for verify to read, so a reset fixture clears
    # it first -- otherwise a second run in the same build directory reopens the previous database
    # and recovers it instead of creating a fresh one
    set(PORTABLE_DB_DIR ${CMAKE_CURRENT_BINARY_DIR}/portability_db)
    add_test(NAME portability_reset COMMAND ${CMAKE_COMMAND} -E rm -rf ${PORTABLE_DB_DIR})
    add_test(NAME portability_create COMMAND portable_db_create
             WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
    add_test(NAME portability_verify COMMAND portable_db_verify
             WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
    set_tests_properties(portability_reset PROPERTIES FIXTURES_SETUP portable_db_reset)
    set_tests_properties(portability_create PROPERTIES
                         FIXTURES_SETUP portable_db FIXTURES_REQUIRED portable_db_reset)
    set_tests_properties(portability_verify PROPERTIES FIXTURES_REQUIRED portable_db)
    set_tests_properties(portability_create portability_verify PROPERTIES
                         ENVIRONMENT TIDESDB_PORTABLE_DIR=${PORTABLE_DB_DIR})

    # copy required DLLs to build directory for Windows (MSVC and MinGW)
    if(WIN32)
        set(TIDESDB_TEST_TARGETS
                block_manager_tests skip_list_tests compress_tests bloom_filter_tests
                pr_filter_tests manifest_tests queue_tests)

        if(MINGW)
            # On MinGW (MSYS2), the test exes link against shared snappy/zstd/lz4
            # plus the MinGW C/C++ runtimes. Copy the DLLs next to each exe so
            # Windows loads them from the exe directory rather than by PATH order
            # (the runner has multiple gcc toolchains on PATH).
            set(MINGW_RUNTIME_BIN "$ENV{MINGW_PREFIX}/bin")
            file(GLOB MINGW_RUNTIME_DLLS
                    "${MINGW_RUNTIME_BIN}/libsnappy*.dll"
                    "${MINGW_RUNTIME_BIN}/libzstd*.dll"
                    "${MINGW_RUNTIME_BIN}/liblz4*.dll"
                    "${MINGW_RUNTIME_BIN}/libstdc++*.dll"
                    "${MINGW_RUNTIME_BIN}/libgcc_s*.dll"
                    "${MINGW_RUNTIME_BIN}/libwinpthread*.dll"
            )
            if(MINGW_RUNTIME_DLLS)
                foreach(test_target ${TIDESDB_TEST_TARGETS})
                    add_custom_command(TARGET ${test_target} POST_BUILD
                            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                            ${MINGW_RUNTIME_DLLS}
                            $<TARGET_FILE_DIR:${test_target}>
                            COMMENT "Copying MinGW runtime DLLs to ${test_target} directory"
                    )
                endforeach()
            endif()
        else()
            # determine vcpkg triplet based on target architecture
            if(CMAKE_SIZEOF_VOID_P EQUAL 8)
                set(VCPKG_TARGET_TRIPLET "x64-windows")
            else()
                set(VCPKG_TARGET_TRIPLET "x86-windows")
            endif()

            # get DLLs from the correct vcpkg directory
            file(GLOB VCPKG_DLLS
                    "${CMAKE_CURRENT_BINARY_DIR}/vcpkg_installed/${VCPKG_TARGET_TRIPLET}/bin/*.dll"
                    "${CMAKE_CURRENT_BINARY_DIR}/vcpkg_installed/${VCPKG_TARGET_TRIPLET}/debug/bin/*.dll"
            )

            if(VCPKG_DLLS)
                # copy DLLs to build directory after building tests
                foreach(test_target ${TIDESDB_TEST_TARGETS})
                    add_custom_command(TARGET ${test_target} POST_BUILD
                            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                            ${VCPKG_DLLS}
                            $<TARGET_FILE_DIR:${test_target}>
                            COMMENT "Copying DLLs to ${test_target} directory"
                    )
                endforeach()
            endif()
        endif()
    endif()
endif()

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/TidesDBConfigVersion.cmake"
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY AnyNewerVersion
)

configure_package_config_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/TidesDBConfig.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/TidesDBConfig.cmake"
	INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/tidesdb"
)

install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/TidesDBConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/TidesDBConfigVersion.cmake"
	DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/tidesdb"
)

if(TIDESDB_BUILD_FUZZERS)
    set(TIDESDB_FUZZ_MODEL fuzz/fuzz_model.c fuzz/fuzz_harness.c fuzz/fuzz_verify.c
                           fuzz/fuzz_durability.c)

    # the standalone/ci runner: no libFuzzer, so it builds with any compiler and runs a fixed number
    # of deterministic pseudo-random inputs (or replays given files) as a regression test
    add_executable(fuzz_standalone fuzz/fuzz_main.c ${TIDESDB_FUZZ_MODEL})
    target_compile_definitions(fuzz_standalone PRIVATE FUZZ_STANDALONE)
    target_include_directories(fuzz_standalone PRIVATE include src external fuzz)
    target_link_libraries(fuzz_standalone PRIVATE tidesdb)

    # the crash/recovery harness: forks a child that commits under a full sync barrier, kills it, then
    # reopens and checks the durability bounds. standalone (any compiler)
    add_executable(fuzz_crash fuzz/fuzz_crash.c fuzz/fuzz_model.c)
    target_include_directories(fuzz_crash PRIVATE include src external fuzz)
    target_link_libraries(fuzz_crash PRIVATE tidesdb)

    # the concurrency harness: worker threads over disjoint key partitions hammer one shared database so
    # the oracle stays exact per worker while the shared memtable, wal, flush, compaction, cache, and
    # value log race. standalone (any compiler)
    add_executable(fuzz_conc fuzz/fuzz_conc.c fuzz/fuzz_model.c)
    target_include_directories(fuzz_conc PRIVATE include src external fuzz)
    target_link_libraries(fuzz_conc PRIVATE tidesdb)

    # the on-disk decoder target: the model harnesses only ever decode bytes the engine itself
    # wrote, so the decoders are the one place untrusted input enters and the only place a torn or
    # corrupt file can turn into an overread. standalone (any compiler)
    add_executable(fuzz_decode fuzz/fuzz_decode.c)
    target_compile_definitions(fuzz_decode PRIVATE FUZZ_STANDALONE)
    target_include_directories(fuzz_decode PRIVATE include src external fuzz)
    target_link_libraries(fuzz_decode PRIVATE tidesdb)

    if(TIDESDB_BUILD_TESTS)
        add_test(NAME fuzz_standalone COMMAND fuzz_standalone)
        add_test(NAME fuzz_crash COMMAND fuzz_crash)
        add_test(NAME fuzz_decode COMMAND fuzz_decode)
        add_test(NAME fuzz_conc COMMAND fuzz_conc)

        # replay the pinned crash corpus so known regressions stay covered regardless of the seed stream
        file(GLOB TIDESDB_CRASH_CORPUS "${CMAKE_CURRENT_SOURCE_DIR}/fuzz/corpus/crash/*.bin")
        if(TIDESDB_CRASH_CORPUS)
            add_test(NAME fuzz_crash_corpus COMMAND fuzz_crash ${TIDESDB_CRASH_CORPUS})

            # the generated run and the corpus replay are the same binary over the same scratch
            # directory, so ctest -j would otherwise start them concurrently and they would tear
            # down each other's database mid-run
            set_tests_properties(fuzz_crash fuzz_crash_corpus PROPERTIES RESOURCE_LOCK tidesdb_crashdb)
        endif()

        # and the model fuzzer's own pinned inputs, so a case it once found is replayed every run
        # rather than waiting on the seed stream to produce it again
        file(GLOB TIDESDB_MODEL_CORPUS "${CMAKE_CURRENT_SOURCE_DIR}/fuzz/corpus/model/*.bin")
        if(TIDESDB_MODEL_CORPUS)
            add_test(NAME fuzz_standalone_corpus COMMAND fuzz_standalone ${TIDESDB_MODEL_CORPUS})
            set_tests_properties(fuzz_standalone fuzz_standalone_corpus PROPERTIES RESOURCE_LOCK
                                 tidesdb_fuzzdb)
        endif()

        # and the inputs the decoder target found, for the same reason
        file(GLOB TIDESDB_DECODE_CORPUS "${CMAKE_CURRENT_SOURCE_DIR}/fuzz/corpus/decode/*.bin")
        if(TIDESDB_DECODE_CORPUS)
            add_test(NAME fuzz_decode_corpus COMMAND fuzz_decode ${TIDESDB_DECODE_CORPUS})
        endif()
    endif()

    # the libFuzzer coverage-guided target, Clang only
    if(CMAKE_C_COMPILER_ID MATCHES "Clang")
        # a second, instrumented copy of the library, linked only by the targets below. guided
        # fuzzing needs the engine itself instrumented or a run explores the harness and nothing
        # else, but the coverage callbacks may only exist in binaries that carry libFuzzer's
        # runtime to service them -- which is these targets and no others. it is defined here, after
        # every property of the shipping library is set, so it can inherit them.
        add_library(tidesdb_cov STATIC ${TIDESDB_SOURCES})
        target_compile_options(tidesdb_cov PRIVATE -fsanitize=fuzzer-no-link)
        target_include_directories(tidesdb_cov PRIVATE src)
        target_include_directories(tidesdb_cov
                PUBLIC $<TARGET_PROPERTY:tidesdb,INTERFACE_INCLUDE_DIRECTORIES>)
        target_compile_definitions(tidesdb_cov
                PRIVATE $<TARGET_PROPERTY:tidesdb,COMPILE_DEFINITIONS>
                PUBLIC $<TARGET_PROPERTY:tidesdb,INTERFACE_COMPILE_DEFINITIONS>)
        target_link_libraries(tidesdb_cov PUBLIC $<TARGET_PROPERTY:tidesdb,LINK_LIBRARIES>)

        add_executable(fuzz_tidesdb fuzz/fuzz_main.c ${TIDESDB_FUZZ_MODEL})
        target_include_directories(fuzz_tidesdb PRIVATE include src external fuzz)
        target_compile_options(fuzz_tidesdb PRIVATE -fsanitize=fuzzer)
        target_link_options(fuzz_tidesdb PRIVATE -fsanitize=fuzzer)
        target_link_libraries(fuzz_tidesdb PRIVATE tidesdb_cov)

        add_executable(fuzz_decode_guided fuzz/fuzz_decode.c)
        target_include_directories(fuzz_decode_guided PRIVATE include src external fuzz)
        target_compile_options(fuzz_decode_guided PRIVATE -fsanitize=fuzzer)
        target_link_options(fuzz_decode_guided PRIVATE -fsanitize=fuzzer)
        target_link_libraries(fuzz_decode_guided PRIVATE tidesdb_cov)
    endif()
endif()

if(TIDESDB_BUILD_BENCH)
    add_executable(tidesdb_bench bench/tidesdb_bench.c bench/bench_workloads.c bench/bench_sample.c)
    target_include_directories(tidesdb_bench PRIVATE include src external bench)
    target_link_libraries(tidesdb_bench PRIVATE tidesdb)
    # the zipfian generator uses pow/log from libm on unix toolchains
    if(NOT MSVC)
        target_link_libraries(tidesdb_bench PRIVATE m)
    endif()

endif()
