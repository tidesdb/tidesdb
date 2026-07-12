cmake_minimum_required(VERSION 3.25)

# mimalloc option must be defined before project() for vcpkg manifest features
option(TIDESDB_WITH_MIMALLOC "Use mimalloc as the memory allocator" OFF)
option(TIDESDB_WITH_TCMALLOC "Use tcmalloc as the memory allocator" OFF)
option(TIDESDB_WITH_JEMALLOC "Use jemalloc as the memory allocator" OFF)

# enable vcpkg mimalloc feature when TIDESDB_WITH_MIMALLOC is ON
# this must be set before project() for vcpkg to pick it up
if(TIDESDB_WITH_MIMALLOC)
    list(APPEND VCPKG_MANIFEST_FEATURES "mimalloc")
endif()

project(tidesdb
	VERSION 9.3.13
	LANGUAGES C)

set(CMAKE_C_STANDARD 11)

# build everything position-independent so the static archive (BUILD_SHARED_LIBS=OFF)
# can still link into a shared module like the mariadb plugin without recompile-with-fPIC errors
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# when building for production releases, you/we want to disable all warnings and sanitizers
option(TIDESDB_WITH_SANITIZER "build with sanitizer in tidesdb" OFF)
option(TIDESDB_BUILD_TESTS "enable building tests in tidesdb" ON)
option(ENABLE_READ_PROFILING "Enable read profiling instrumentation" OFF)
option(TIDESDB_WITH_S3 "build S3-compatible object store connector (requires libcurl only)" OFF)

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

# mirror TIDESDB_WITH_S3 into TIDESDB_HAS_S3 so configure_file emits the consumer-visible define
if(TIDESDB_WITH_S3)
    set(TIDESDB_HAS_S3 ON)
endif()

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

if(ENABLE_READ_PROFILING)
    add_compile_definitions(TDB_ENABLE_READ_PROFILING)
endif()

if(MINGW)
    add_compile_definitions(__USE_MINGW_ANSI_STDIO=1)
endif()

# expose glibc extensions on linux (fallocate, etc.) for compat.h helpers
if(UNIX AND NOT APPLE)
    add_compile_definitions(_GNU_SOURCE)
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

# for development, we want to enable all warnings and sanitizers
if(TIDESDB_WITH_SANITIZER)
    if(MSVC)
        # debug flags for MSVC
        # MSVC ASAN can be unstable, so we only enable warnings for CI
        # suppress noisy warnings 4311 (pointer truncation), 4244 (conversion), 4047 (pointer indirection)
        # 4267 (size_t to smaller type conversion), 4127 (constant expression in conditional),
        # 4305 (type truncation),
        # 4702 (unreachable code -- triggered inside uthash macro expansions in the bench)
        add_compile_options(/W4 /std:c17 /experimental:c11atomics /wd4311 /wd4244 /wd4267 /wd4047 /wd4189 /wd4101 /wd4459 /wd4127 /wd4305 /wd4702)
    elseif(MINGW)
        # MinGW/GCC flags
        add_compile_options(-Wextra -Wall -std=c11)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD" OR CMAKE_SYSTEM_NAME STREQUAL "DragonFly" OR CMAKE_SYSTEM_NAME STREQUAL "SunOS")
        # ASan is not supported on OpenBSD, DragonFlyBSD, and OmniOS/Illumos
        add_compile_options(-Wextra -Wall)
    elseif(CMAKE_SYSTEM_NAME MATCHES "BSD")
        # FreeBSD, NetBSD support sanitizers
        add_compile_options(-Wextra -Wall -fsanitize=address,undefined)
        add_link_options(-fsanitize=address,undefined)
    else()
        # Unix/Linux/macOS flags
        add_compile_options(-Wextra -Wall -fsanitize=address,undefined)
        add_link_options(-fsanitize=address,undefined)
    endif()
else()
    if(MSVC)
        # ensure C17 support and C11 atomics are enabled even without sanitizers
        # disable common test warnings that clutter output:
        # 4189: local variable initialized but not referenced
        # 4101: unreferenced local variable
        # 4459: declaration hides global declaration
        # 4700: uninitialized local variable used
        # 4013: undefined function (implicit declaration)
        # 4702: unreachable code (triggered inside uthash macro expansions in the bench)
        add_compile_options(/std:c17 /experimental:c11atomics /wd4189 /wd4101 /wd4459 /wd4700 /wd4013 /wd4702)
    elseif(MINGW)
        # MinGW/GCC flags without sanitizers
        add_compile_options(-std=c11)
    endif()
endif()

include_directories(external) # for external libraries linking internally

# create library (respects BUILD_SHARED_LIBS option)
# note on Windows, STATIC is recommended to avoid DLL export/import complexity
# users can override with -DBUILD_SHARED_LIBS=ON/OFF
set(TIDESDB_SOURCES
    src/tidesdb.c src/block_manager.c src/skip_list.c src/compress.c src/bloom_filter.c
    src/manifest.c src/clock_cache.c src/queue.c src/btree.c src/alloc.c
    src/objstore_fs.c src/local_cache.c src/sha256.c src/hmac_sha256.c
    external/xxhash.c external/ini.c)

if(TIDESDB_WITH_S3)
    list(APPEND TIDESDB_SOURCES src/objstore_s3.c)
endif()

add_library(tidesdb ${TIDESDB_SOURCES})

set_target_properties(tidesdb PROPERTIES
	                      VERSION "${PROJECT_VERSION}"
                              SOVERSION "${PROJECT_VERSION_MAJOR}")

target_include_directories(tidesdb PRIVATE src)

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
#      which a bare -l<name> cannot -- this is what issue #618 hit on Ubuntu.
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

# find compression libraries.
# MSVC builds rely on vcpkg, which ships full CMake config packages.
# MinGW (MSYS2) zstd and lz4 ship only pkg-config (.pc) files, no CMake
# configs, so use PkgConfig for them. snappy is the opposite, upstream
# snappy installs SnappyConfig.cmake but no .pc (so the x86 from-source
# build in CI cannot use pkg-config), while MSYS2's prebuilt snappy ships
# both. CONFIG mode works for snappy across all three setups.
# winpthreads is bundled with the MinGW toolchain so we link plain pthread.
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
    # macOS supports multiple package managers (Homebrew, MacPorts, pkgsrc, Fink, etc)
    # we allow user to specify custom paths via -DMACOS_DEPENDENCY_PREFIX=/path
    # or use -DUSE_HOMEBREW=ON/OFF to control Homebrew detection (the default is ON)

    option(USE_HOMEBREW "Auto-detect and use Homebrew paths on macOS" ON)

    if(DEFINED MACOS_DEPENDENCY_PREFIX)
        # user explicitly specified a prefix (e.g., MacPorts /opt/local, pkgsrc /usr/pkg)
        message(STATUS "Using custom macOS dependency prefix: ${MACOS_DEPENDENCY_PREFIX}")
        target_include_directories(tidesdb PUBLIC ${MACOS_DEPENDENCY_PREFIX}/include)
        target_link_directories(tidesdb PUBLIC ${MACOS_DEPENDENCY_PREFIX}/lib)
    elseif(USE_HOMEBREW)
        # auto-detect homebrew installation
        if(CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64")
            # Apple Silicon -- Homebrew uses /opt/homebrew
            set(HOMEBREW_PREFIX "/opt/homebrew")
        else()
            # Intel Mac -- Homebrew uses /usr/local
            set(HOMEBREW_PREFIX "/usr/local")
        endif()

        # verify homebrew prefix exists before using it
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

    # Link against compression libraries for macOS
    target_link_libraries(tidesdb PUBLIC
            m           # math library
            pthread     # pthread library
    )
    # resolve compression backends via override -> known target -> -l fallback (issue #618)
    _tidesdb_link_enabled_compression()

    if(CMAKE_SIZEOF_VOID_P EQUAL 4)
        target_link_libraries(tidesdb PUBLIC atomic)
    endif()

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
elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    # FreeBSD packages installed in /usr/local
    target_include_directories(tidesdb PUBLIC /usr/local/include)
    target_link_directories(tidesdb PUBLIC /usr/local/lib)
    target_link_libraries(tidesdb PUBLIC
            m           # math library
            pthread     # pthread library
    )
    # resolve compression backends via override -> known target -> -l fallback (issue #618)
    _tidesdb_link_enabled_compression()

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
elseif(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
    # OpenBSD -- packages installed in /usr/local
    target_include_directories(tidesdb PUBLIC /usr/local/include)
    target_link_directories(tidesdb PUBLIC /usr/local/lib)
    target_link_libraries(tidesdb PUBLIC
            m           # math library
            pthread     # pthread library
    )
    # resolve compression backends via override -> known target -> -l fallback (issue #618)
    _tidesdb_link_enabled_compression()

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
elseif(CMAKE_SYSTEM_NAME STREQUAL "NetBSD")
    # NetBSD -- packages installed in /usr/pkg
    target_include_directories(tidesdb PUBLIC /usr/pkg/include)
    target_link_directories(tidesdb PUBLIC /usr/pkg/lib)
    target_link_libraries(tidesdb PUBLIC
            m           # math library
            pthread     # pthread library
    )
    # resolve compression backends via override -> known target -> -l fallback (issue #618)
    _tidesdb_link_enabled_compression()

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
elseif(CMAKE_SYSTEM_NAME STREQUAL "DragonFly")
    # DragonFlyBSD -- packages installed in /usr/local
    target_include_directories(tidesdb PUBLIC /usr/local/include)
    target_link_directories(tidesdb PUBLIC /usr/local/lib)
    target_link_libraries(tidesdb PUBLIC
            m           # math library
            pthread     # pthread library
    )
    # resolve compression backends via override -> known target -> -l fallback (issue #618)
    _tidesdb_link_enabled_compression()

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
    # resolve compression backends via override -> known target -> -l fallback (snappy off here)
    _tidesdb_link_enabled_compression()

    if(TIDESDB_WITH_MIMALLOC)
        target_link_libraries(tidesdb PUBLIC mimalloc)
    endif()

    if(TIDESDB_WITH_TCMALLOC)
        target_link_libraries(tidesdb PUBLIC ${TCMALLOC_LIBRARIES})
        target_include_directories(tidesdb PUBLIC ${TCMALLOC_INCLUDE_DIRS})
    endif()
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
endif()

# S3 connector (platform-independent, requires libcurl only 
if(TIDESDB_WITH_S3)
    find_package(CURL REQUIRED)
    target_compile_definitions(tidesdb PRIVATE TIDESDB_WITH_S3)
    target_link_libraries(tidesdb PUBLIC CURL::libcurl)
    message(STATUS "Building with S3-compatible object store connector")
endif()

include(GNUInstallDirs)
install(TARGETS tidesdb
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})

install(DIRECTORY src/ DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/tidesdb" FILES_MATCHING PATTERN "*.h")
install(FILES external/ini.h external/xxhash.h DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/tidesdb")
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/tidesdb_version.h" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/tidesdb")

# we create consolidated include directory in build tree for easy consumption
# this allows consumers to use -I<build_dir>/include and #include <tidesdb/tidesdb.h>
set(BUILD_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/include/tidesdb")
file(MAKE_DIRECTORY ${BUILD_INCLUDE_DIR})

# copy all public headers to build include directory
file(GLOB SRC_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.h")
file(GLOB EXT_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/external/*.h")
file(COPY ${SRC_HEADERS} DESTINATION ${BUILD_INCLUDE_DIR})
file(COPY ${EXT_HEADERS} DESTINATION ${BUILD_INCLUDE_DIR})

# copy generated version header (done at build time since it's generated)
add_custom_command(TARGET tidesdb POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_CURRENT_BINARY_DIR}/tidesdb_version.h"
        "${BUILD_INCLUDE_DIR}/tidesdb_version.h"
        COMMENT "Copying tidesdb_version.h to build include directory"
)

if(TIDESDB_BUILD_TESTS) # enable building tests and benchmarks
    enable_testing()

    # benchmark configuration variables (can be overridden at build time with -D flags)
    if(NOT DEFINED BENCH_NUM_OPERATIONS)
        set(BENCH_NUM_OPERATIONS 10000000)
    endif()
    if(NOT DEFINED BENCH_NUM_SEEK_OPS)
        set(BENCH_NUM_SEEK_OPS 100)
    endif()
    if(NOT DEFINED BENCH_KEY_SIZE)
        set(BENCH_KEY_SIZE 16)
    endif()
    if(NOT DEFINED BENCH_VALUE_SIZE)
        set(BENCH_VALUE_SIZE 100)
    endif()
    if(NOT DEFINED BENCH_CF_NAME)
        set(BENCH_CF_NAME "benchmark_cf")
    endif()
    if(NOT DEFINED BENCH_NUM_THREADS)
        set(BENCH_NUM_THREADS 8)
    endif()
    if(NOT DEFINED BENCH_KEY_PATTERN)
        set(BENCH_KEY_PATTERN "random")
    endif()

    # tidesdb config variables for benchmark
    if(NOT DEFINED BENCH_DB_LOG_LEVEL)
        set(BENCH_DB_LOG_LEVEL TDB_LOG_DEBUG)
    endif()
    if(NOT DEFINED BENCH_DB_PATH)
        set(BENCH_DB_PATH "benchmark_db")
    endif()
    if(NOT DEFINED BENCH_DB_FLUSH_POOL_THREADS)
        set(BENCH_DB_FLUSH_POOL_THREADS 2)
    endif()
    if(NOT DEFINED BENCH_DB_COMPACTION_POOL_THREADS)
        set(BENCH_DB_COMPACTION_POOL_THREADS 2)
    endif()
    if(NOT DEFINED BENCH_DB_MAX_MEMORY)
        math(EXPR BENCH_DB_MAX_MEMORY 0) # 0 defaults to 75% of system memory
    endif()

    # column family configuration variables for benchmark
    if(NOT DEFINED BENCH_WRITE_BUFFER_SIZE)
        math(EXPR BENCH_WRITE_BUFFER_SIZE 67108864)
    endif()
    if(NOT DEFINED BENCH_LEVEL_RATIO)
        set(BENCH_LEVEL_RATIO 10)
    endif()
    if(NOT DEFINED BENCH_DIVIDING_LEVEL_OFFSET)
        set(BENCH_DIVIDING_LEVEL_OFFSET 2)
    endif()
    if(NOT DEFINED BENCH_MIN_LEVELS)
        set(BENCH_MIN_LEVELS 5)
    endif()
    if(NOT DEFINED BENCH_SKIP_LIST_MAX_LEVEL)
        set(BENCH_SKIP_LIST_MAX_LEVEL 12)
    endif()
    if(NOT DEFINED BENCH_SKIP_LIST_PROBABILITY)
        set(BENCH_SKIP_LIST_PROBABILITY 0.25)
    endif()
    if(NOT DEFINED BENCH_ENABLE_COMPRESSION)
        set(BENCH_ENABLE_COMPRESSION 1)
    endif()
    if(NOT DEFINED BENCH_COMPRESSION_ALGORITHM)
        set(BENCH_COMPRESSION_ALGORITHM TDB_COMPRESS_LZ4)
    endif()
    if(NOT DEFINED BENCH_ENABLE_BLOOM_FILTER)
        set(BENCH_ENABLE_BLOOM_FILTER 1)
    endif()
    if(NOT DEFINED BENCH_BLOOM_FILTER_FP_RATE)
        set(BENCH_BLOOM_FILTER_FP_RATE 0.01)
    endif()
    if(NOT DEFINED BENCH_ENABLE_BLOCK_INDEXES)
        set(BENCH_ENABLE_BLOCK_INDEXES 1)
    endif()
    if(NOT DEFINED BENCH_BLOCK_INDEX_SAMPLING_COUNT)
        set(BENCH_BLOCK_INDEX_SAMPLING_COUNT 1)
    endif()
    if(NOT DEFINED BENCH_BLOCK_INDEX_PREFIX_LEN)
        set(BENCH_BLOCK_INDEX_PREFIX_LEN 16)
    endif()
    if(NOT DEFINED BENCH_SYNC_MODE)
        set(BENCH_SYNC_MODE TDB_SYNC_NONE)
    endif()
    if(NOT DEFINED BENCH_SYNC_INTERVAL_US)
        set(BENCH_SYNC_INTERVAL_US 128000)
    endif()
    if(NOT DEFINED BENCH_COMPARATOR_NAME)
        set(BENCH_COMPARATOR_NAME "memcmp")
    endif()
    if (NOT DEFINED BENCH_BLOCK_CACHE_SIZE)
        math(EXPR BENCH_BLOCK_CACHE_SIZE 67108864)
    endif()
    if(NOT DEFINED BENCH_ISOLATION_LEVEL)
        set(BENCH_ISOLATION_LEVEL TDB_ISOLATION_READ_COMMITTED)
    endif()
    if(NOT DEFINED BENCH_KLOG_VALUE_THRESHOLD)
        math(EXPR BENCH_KLOG_VALUE_THRESHOLD 512)
    endif()
    if(NOT DEFINED BENCH_MIN_DISK_SPACE)
        math(EXPR BENCH_MIN_DISK_SPACE 104857600)
    endif()
    if(NOT DEFINED BENCH_L1_FILE_COUNT_TRIGGER)
        set(BENCH_L1_FILE_COUNT_TRIGGER 4)
    endif()
    if(NOT DEFINED BENCH_L0_QUEUE_STALL_THRESHOLD)
        set(BENCH_L0_QUEUE_STALL_THRESHOLD 20)
    endif()
    if(NOT DEFINED BENCH_MAX_OPEN_SSTABLES)
        set(BENCH_MAX_OPEN_SSTABLES 256)
    endif()
    if(NOT DEFINED BENCH_USE_BTREE)
        set(BENCH_USE_BTREE 0)
    endif()

    add_executable(block_manager_tests test/block_manager__tests.c)
    add_executable(skip_list_tests test/skip_list__tests.c)
    add_executable(compress_tests test/compress__tests.c)
    add_executable(bloom_filter_tests test/bloom_filter__tests.c)
    add_executable(clock_cache_tests test/clock_cache__tests.c)
    add_executable(manifest_tests test/manifest__tests.c)
    add_executable(queue_tests test/queue__tests.c)
    add_executable(btree_tests test/btree__tests.c)
    add_executable(local_cache_tests test/local_cache__tests.c)
    add_executable(objstore_tests test/objstore__tests.c)
    add_executable(sha256_tests test/sha256__tests.c)
    add_executable(hmac_sha256_tests test/hmac_sha256__tests.c)
    add_executable(tidesdb_tests test/tidesdb__tests.c)
    if(TIDESDB_WITH_S3)
        target_compile_definitions(tidesdb_tests PRIVATE TIDESDB_WITH_S3)
        target_compile_definitions(objstore_tests PRIVATE TIDESDB_WITH_S3)
    endif()
    add_executable(tidesdb_bench bench/tidesdb__bench.c)

    # pass benchmark configuration as compile definitions
    target_compile_definitions(tidesdb_bench PRIVATE
            BENCH_NUM_OPERATIONS=${BENCH_NUM_OPERATIONS}
            BENCH_NUM_SEEK_OPS=${BENCH_NUM_SEEK_OPS}
            BENCH_KEY_SIZE=${BENCH_KEY_SIZE}
            BENCH_VALUE_SIZE=${BENCH_VALUE_SIZE}
            BENCH_CF_NAME=\"${BENCH_CF_NAME}\"
            BENCH_NUM_THREADS=${BENCH_NUM_THREADS}
            BENCH_DB_LOG_LEVEL=${BENCH_DB_LOG_LEVEL}
            BENCH_DB_PATH=\"${BENCH_DB_PATH}\"
            BENCH_DB_MAX_MEMORY=${BENCH_DB_MAX_MEMORY}
            BENCH_KEY_PATTERN=\"${BENCH_KEY_PATTERN}\"
            BENCH_WRITE_BUFFER_SIZE=${BENCH_WRITE_BUFFER_SIZE}
            BENCH_LEVEL_RATIO=${BENCH_LEVEL_RATIO}
            BENCH_DIVIDING_LEVEL_OFFSET=${BENCH_DIVIDING_LEVEL_OFFSET}
            BENCH_MIN_LEVELS=${BENCH_MIN_LEVELS}
            BENCH_SKIP_LIST_MAX_LEVEL=${BENCH_SKIP_LIST_MAX_LEVEL}
            BENCH_SKIP_LIST_PROBABILITY=${BENCH_SKIP_LIST_PROBABILITY}
            BENCH_ENABLE_COMPRESSION=${BENCH_ENABLE_COMPRESSION}
            BENCH_COMPRESSION_ALGORITHM=${BENCH_COMPRESSION_ALGORITHM}
            BENCH_ENABLE_BLOOM_FILTER=${BENCH_ENABLE_BLOOM_FILTER}
            BENCH_BLOOM_FILTER_FP_RATE=${BENCH_BLOOM_FILTER_FP_RATE}
            BENCH_ENABLE_BLOCK_INDEXES=${BENCH_ENABLE_BLOCK_INDEXES}
            BENCH_BLOCK_INDEX_SAMPLING_COUNT=${BENCH_BLOCK_INDEX_SAMPLING_COUNT}
            BENCH_BLOCK_INDEX_PREFIX_LEN=${BENCH_BLOCK_INDEX_PREFIX_LEN}
            BENCH_SYNC_MODE=${BENCH_SYNC_MODE}
            BENCH_SYNC_INTERVAL_US=${BENCH_SYNC_INTERVAL_US}
            BENCH_COMPARATOR_NAME="${BENCH_COMPARATOR_NAME}"
            BENCH_BLOCK_CACHE_SIZE=${BENCH_BLOCK_CACHE_SIZE}
    )

    # enable read profiling if requested
    if(ENABLE_READ_PROFILING)
        target_compile_definitions(tidesdb_bench PRIVATE TDB_ENABLE_READ_PROFILING)
    endif()

    target_compile_definitions(tidesdb_bench PRIVATE
            BENCH_DB_FLUSH_POOL_THREADS=${BENCH_DB_FLUSH_POOL_THREADS}
            BENCH_DB_COMPACTION_POOL_THREADS=${BENCH_DB_COMPACTION_POOL_THREADS}
            BENCH_ISOLATION_LEVEL=${BENCH_ISOLATION_LEVEL}
            BENCH_KLOG_VALUE_THRESHOLD=${BENCH_KLOG_VALUE_THRESHOLD}
            BENCH_MIN_DISK_SPACE=${BENCH_MIN_DISK_SPACE}
            BENCH_L1_FILE_COUNT_TRIGGER=${BENCH_L1_FILE_COUNT_TRIGGER}
            BENCH_L0_QUEUE_STALL_THRESHOLD=${BENCH_L0_QUEUE_STALL_THRESHOLD}
            BENCH_MAX_OPEN_SSTABLES=${BENCH_MAX_OPEN_SSTABLES}
            BENCH_USE_BTREE=${BENCH_USE_BTREE}
    )

    # failover harness node -- a minimal networked tidesdb instance (one process = one cluster
    # node) driven by the object-store failover tests in test/failover. POSIX sockets, so it is
    # not built on Windows.
    if(NOT WIN32)
        add_executable(tidesdb_node test/failover/tidesdb_node.c)
        target_link_libraries(tidesdb_node PRIVATE tidesdb)
        target_include_directories(tidesdb_node PRIVATE src external)
        if(TIDESDB_WITH_S3)
            target_compile_definitions(tidesdb_node PRIVATE TIDESDB_WITH_S3)
        endif()
        # on illumos/Solaris the socket calls live in libsocket/libnsl, not libc
        if(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
            target_link_libraries(tidesdb_node PRIVATE socket nsl)
        endif()
    endif()

    # add include and link directories for test executables
    foreach(test_target block_manager_tests skip_list_tests compress_tests bloom_filter_tests manifest_tests clock_cache_tests queue_tests btree_tests local_cache_tests objstore_tests sha256_tests hmac_sha256_tests tidesdb_tests tidesdb_bench)
        target_link_libraries(${test_target} PRIVATE tidesdb)
        target_include_directories(${test_target} PRIVATE external)
    endforeach()

    add_test(NAME block_manager_tests COMMAND block_manager_tests)
    add_test(NAME skip_list_tests COMMAND skip_list_tests)
    add_test(NAME compress_tests COMMAND compress_tests)
    add_test(NAME bloom_filter_tests COMMAND bloom_filter_tests)
    add_test(NAME manifest_tests COMMAND manifest_tests)
    add_test(NAME clock_cache_tests COMMAND clock_cache_tests)
    add_test(NAME queue_tests COMMAND queue_tests)
    add_test(NAME btree_tests COMMAND btree_tests)
    add_test(NAME local_cache_tests COMMAND local_cache_tests)
    add_test(NAME objstore_tests COMMAND objstore_tests)
    add_test(NAME sha256_tests COMMAND sha256_tests)
    add_test(NAME hmac_sha256_tests COMMAND hmac_sha256_tests)
    add_test(NAME tidesdb_tests COMMAND tidesdb_tests)

    # copy required DLLs to build directory for Windows (MSVC and MinGW)
    if(WIN32)
        set(TIDESDB_TEST_TARGETS
                block_manager_tests skip_list_tests compress_tests bloom_filter_tests
                manifest_tests queue_tests tidesdb_tests tidesdb_bench)

        if(MINGW)
            # On MinGW (MSYS2), the test exes link against shared snappy/zstd/lz4
            # plus the MinGW C/C++ runtimes. Copy the DLLs next to each exe so
            # Windows loads them from the exe directory and we do not depend on
            # PATH order (the runner has multiple gcc toolchains on PATH).
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

            # only proceed if we found DLLs
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
