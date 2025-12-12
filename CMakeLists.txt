cmake_minimum_required(VERSION 3.25)
project(tidesdb C)

set(CMAKE_C_STANDARD 11)
set(PROJECT_VERSION 6.0.0)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/src/tidesdb_version.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/tidesdb_version.h"
)

# when building for production releases, you/we want to disable all warnings and sanitizers
option(TIDESDB_WITH_SANITIZER "build with sanitizer in tidesdb" ON)
option(TIDESDB_BUILD_TESTS "enable building tests in tidesdb" ON)
option(BUILD_SHARED_LIBS "Build using shared libraries" ON)

if(MINGW)
    add_compile_definitions(__USE_MINGW_ANSI_STDIO=1)
endif()

if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    if(NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 11.0)
        add_compile_options(-Wno-psabi)
    endif()
endif()

# for development, we want to enable all warnings and sanitizers
if(TIDESDB_WITH_SANITIZER)
    if(MSVC)
        # debug flags for MSVC
        # MSVC ASAN can be unstable, so we only enable warnings for CI
        # suppress noisy warnings: 4311 (pointer truncation), 4244 (conversion), 4047 (pointer indirection)
        # 4127 (constant expression in conditional), 4305 (type truncation)
        add_compile_options(/W4 /std:c17 /experimental:c11atomics /wd4311 /wd4244 /wd4047 /wd4189 /wd4101 /wd4459 /wd4127 /wd4305)
    elseif(MINGW)
        # MinGW/GCC flags
        add_compile_options(-Wextra -Wall -std=c11)
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
        add_compile_options(/std:c17 /experimental:c11atomics /wd4189 /wd4101 /wd4459 /wd4700 /wd4013)
    elseif(MINGW)
        # MinGW/GCC flags without sanitizers
        add_compile_options(-std=c11)
    endif()
endif()

include_directories(external) # for external libraries linking internally

# build as STATIC on Windows to avoid DLL export/import complexity in tests
if(WIN32)
    add_library(tidesdb STATIC src/tidesdb.c src/block_manager.c src/skip_list.c src/compress.c src/bloom_filter.c src/lru.c src/queue.c src/buffer.c external/xxhash.c external/ini.c)
else()
    add_library(tidesdb SHARED src/tidesdb.c src/block_manager.c src/skip_list.c src/compress.c src/bloom_filter.c src/lru.c src/queue.c src/buffer.c external/xxhash.c external/ini.c)
endif()

target_include_directories(tidesdb PRIVATE src)

# find compression libraries (use CONFIG mode on Windows with vcpkg)
if(WIN32)
    find_package(zstd CONFIG REQUIRED)
    find_package(Snappy CONFIG REQUIRED)
    find_package(lz4 CONFIG REQUIRED)
    find_package(PThreads4W REQUIRED)
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
            lz4         # lz4 compression
            zstd        # zstandard compression
            snappy      # snappy compression
            pthread     # pthread library
    )

    if(CMAKE_SIZEOF_VOID_P EQUAL 4)
        target_link_libraries(tidesdb PUBLIC atomic)
    endif()
elseif(WIN32)
    # for windows, link against compression libraries and pthreads
    target_link_libraries(tidesdb PUBLIC
            $<IF:$<TARGET_EXISTS:zstd::libzstd_shared>,zstd::libzstd_shared,zstd::libzstd_static>
            Snappy::snappy
            lz4::lz4
            PThreads4W::PThreads4W
    )
elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    # FreeBSD packages installed in /usr/local
    target_include_directories(tidesdb PUBLIC /usr/local/include)
    target_link_directories(tidesdb PUBLIC /usr/local/lib)
    target_link_libraries(tidesdb PUBLIC
            m           # math library
            lz4         # lz4 compression
            zstd        # zstandard compression
            snappy      # snappy compression
            pthread     # pthread library
    )
elseif(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
    # OpenBSD -- packages installed in /usr/local
    target_include_directories(tidesdb PUBLIC /usr/local/include)
    target_link_directories(tidesdb PUBLIC /usr/local/lib)
    target_link_libraries(tidesdb PUBLIC
            m           # math library
            lz4         # lz4 compression
            zstd        # zstandard compression
            snappy      # snappy compression
            pthread     # pthread library
    )
elseif(CMAKE_SYSTEM_NAME STREQUAL "NetBSD")
    # NetBSD -- packages installed in /usr/pkg
    target_include_directories(tidesdb PUBLIC /usr/pkg/include)
    target_link_directories(tidesdb PUBLIC /usr/pkg/lib)
    target_link_libraries(tidesdb PUBLIC
            m           # math library
            lz4         # lz4 compression
            zstd        # zstandard compression
            snappy      # snappy compression
            pthread     # pthread library
    )
elseif(CMAKE_SYSTEM_NAME STREQUAL "DragonFly")
    # DragonFlyBSD -- packages installed in /usr/local
    target_include_directories(tidesdb PUBLIC /usr/local/include)
    target_link_directories(tidesdb PUBLIC /usr/local/lib)
    target_link_libraries(tidesdb PUBLIC
            m           # math library
            lz4         # lz4 compression
            zstd        # zstandard compression
            snappy      # snappy compression
            pthread     # pthread library
    )
elseif(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
    # OmniOS/Illumos -- OpenIndiana Community Edition packages in /opt/ooce
    # Note: snappy is not available in OmniOS repos, using only lz4 and zstd
    target_include_directories(tidesdb PUBLIC /opt/ooce/include /usr/include)
    target_link_directories(tidesdb PUBLIC /opt/ooce/lib/amd64 /usr/lib/amd64)
    target_link_libraries(tidesdb PUBLIC
            m           # math library
            lz4         # lz4 compression
            zstd        # zstandard compression
            pthread     # pthread library
    )
else()
    # for linux and other unix systems
    target_link_libraries(tidesdb PUBLIC
            zstd
            snappy
            lz4
            pthread
            m           # math library
            stdc++      # C++ standard library (required by Snappy)
            atomic      # atomic operations library (required for 32-bit architectures like PowerPC)
    )
endif()

install(TARGETS tidesdb
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)

install(DIRECTORY src/ DESTINATION include/tidesdb FILES_MATCHING PATTERN "*.h")
install(FILES external/ini.h external/xxhash.h DESTINATION include/tidesdb)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/tidesdb_version.h" DESTINATION include/tidesdb)

if(TIDESDB_BUILD_TESTS) # enable building tests and benchmarks
    enable_testing()

    # benchmark configuration variables (can be overridden at build time with -D flags)
    if(NOT DEFINED BENCH_NUM_OPERATIONS)
        set(BENCH_NUM_OPERATIONS 1000000)
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
        set(BENCH_KEY_PATTERN "sequential")
    endif()

    # tidesdb config variables for benchmark
    if(NOT DEFINED BENCH_DB_DEBUG)
        set(BENCH_DB_DEBUG 1)
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
    if(NOT DEFINED BENCH_MAX_LEVELS)
        set(BENCH_MAX_LEVELS 3)
    endif()
    if(NOT DEFINED BENCH_SKIP_LIST_MAX_LEVEL)
        set(BENCH_SKIP_LIST_MAX_LEVEL 16)  
    endif()
    if(NOT DEFINED BENCH_SKIP_LIST_PROBABILITY)
        set(BENCH_SKIP_LIST_PROBABILITY 0.25) 
    endif()
    if(NOT DEFINED BENCH_ENABLE_COMPRESSION)
        set(BENCH_ENABLE_COMPRESSION 1)
    endif()
    if(NOT DEFINED BENCH_COMPRESSION_ALGORITHM)
        set(BENCH_COMPRESSION_ALGORITHM LZ4_COMPRESSION)
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
        set(BENCH_BLOCK_INDEX_SAMPLING_COUNT 16)
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

    add_executable(block_manager_tests test/block_manager__tests.c)
    add_executable(skip_list_tests test/skip_list__tests.c)
    add_executable(compress_tests test/compress__tests.c)
    add_executable(bloom_filter_tests test/bloom_filter__tests.c)
    add_executable(lru_tests test/lru__tests.c)
    add_executable(queue_tests test/queue__tests.c)
    add_executable(buffer_tests test/buffer__tests.c)
    add_executable(tidesdb_tests test/tidesdb__tests.c)
    add_executable(tidesdb_bench bench/tidesdb__bench.c)

    # pass benchmark configuration as compile definitions
    target_compile_definitions(tidesdb_bench PRIVATE
        BENCH_NUM_OPERATIONS=${BENCH_NUM_OPERATIONS}
        BENCH_NUM_SEEK_OPS=${BENCH_NUM_SEEK_OPS}
        BENCH_KEY_SIZE=${BENCH_KEY_SIZE}
        BENCH_VALUE_SIZE=${BENCH_VALUE_SIZE}
        BENCH_CF_NAME=\"${BENCH_CF_NAME}\"
        BENCH_NUM_THREADS=${BENCH_NUM_THREADS}
        BENCH_DB_DEBUG=${BENCH_DB_DEBUG}
        BENCH_DB_PATH=\"${BENCH_DB_PATH}\"
        BENCH_KEY_PATTERN=\"${BENCH_KEY_PATTERN}\"
        BENCH_WRITE_BUFFER_SIZE=${BENCH_WRITE_BUFFER_SIZE}
        BENCH_LEVEL_RATIO=${BENCH_LEVEL_RATIO}
        BENCH_DIVIDING_LEVEL_OFFSET=${BENCH_DIVIDING_LEVEL_OFFSET}
        BENCH_MIN_LEVELS=${BENCH_MAX_LEVELS}
        BENCH_SKIP_LIST_MAX_LEVEL=${BENCH_SKIP_LIST_MAX_LEVEL}
        BENCH_SKIP_LIST_PROBABILITY=${BENCH_SKIP_LIST_PROBABILITY}
        BENCH_ENABLE_COMPRESSION=${BENCH_ENABLE_COMPRESSION}
        BENCH_COMPRESSION_ALGORITHM=${BENCH_COMPRESSION_ALGORITHM}
        BENCH_ENABLE_BLOOM_FILTER=${BENCH_ENABLE_BLOOM_FILTER}
        BENCH_BLOOM_FILTER_FP_RATE=${BENCH_BLOOM_FILTER_FP_RATE}
        BENCH_ENABLE_BLOCK_INDEXES=${BENCH_ENABLE_BLOCK_INDEXES}
        BENCH_BLOCK_INDEX_SAMPLING_COUNT=${BENCH_BLOCK_INDEX_SAMPLING_COUNT}
        BENCH_SYNC_MODE=${BENCH_SYNC_MODE}
        BENCH_SYNC_INTERVAL_US=${BENCH_SYNC_INTERVAL_US}
        BENCH_COMPARATOR_NAME=\"${BENCH_COMPARATOR_NAME}\"
        BENCH_BLOCK_CACHE_SIZE=${BENCH_BLOCK_CACHE_SIZE}
        BENCH_DB_FLUSH_POOL_THREADS=${BENCH_DB_FLUSH_POOL_THREADS}
        BENCH_DB_COMPACTION_POOL_THREADS=${BENCH_DB_COMPACTION_POOL_THREADS}
        BENCH_ISOLATION_LEVEL=${BENCH_ISOLATION_LEVEL}
    )

    # add include and link directories for test executables
    foreach(test_target block_manager_tests skip_list_tests compress_tests bloom_filter_tests lru_tests queue_tests buffer_tests tidesdb_tests tidesdb_bench)
        target_link_libraries(${test_target} PRIVATE tidesdb)
        target_include_directories(${test_target} PRIVATE external)
    endforeach()

    add_test(NAME block_manager_tests COMMAND block_manager_tests)
    add_test(NAME skip_list_tests COMMAND skip_list_tests)
    add_test(NAME compress_tests COMMAND compress_tests)
    add_test(NAME bloom_filter_tests COMMAND bloom_filter_tests)
    add_test(NAME lru_tests COMMAND lru_tests)
    add_test(NAME queue_tests COMMAND queue_tests)
    add_test(NAME buffer_tests COMMAND buffer_tests)
    add_test(NAME tidesdb_tests COMMAND tidesdb_tests)

    # copy required DLLs to build directory for Windows (MSVC and MinGW)
    if(WIN32)
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
            foreach(test_target block_manager_tests skip_list_tests compress_tests bloom_filter_tests lru_tests queue_tests tidesdb_tests tidesdb_bench)
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

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/TidesDBConfigVersion.cmake"
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY AnyNewerVersion
)

configure_package_config_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/TidesDBConfig.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/TidesDBConfig.cmake"
        INSTALL_DESTINATION lib/cmake/tidesdb
)

install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/TidesDBConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/TidesDBConfigVersion.cmake"
        DESTINATION lib/cmake/tidesdb
)