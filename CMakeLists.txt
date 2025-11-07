## cmake build instructions unix
# rm -rf build && cmake -S . -B build
# cmake --build build
# cmake --install build

## cmake build instructions windows
# rmdir /s /q build && cmake -S . -B build
# cmake --build build
# cmake --install build

## or 
# Remove-Item -Recurse -Force build -ErrorAction SilentlyContinue
# cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake
# cmake --build build
# Set-Location build
# ctest --output-on-failure

cmake_minimum_required(VERSION 3.25)
project(tidesdb C)

set(CMAKE_C_STANDARD 11)
set(PROJECT_VERSION 1.0.0) # TidesDB v1.0.0

# when building for production releases, you/we want to disable all warnings and sanitizers
option(TIDESDB_WITH_SANITIZER "build with sanitizer in tidesdb" ON)
option(TIDESDB_BUILD_TESTS "enable building tests in tidesdb" ON)
option(BUILD_SHARED_LIBS "Build using shared libraries" ON)

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
    add_library(tidesdb STATIC src/tidesdb.c src/block_manager.c src/skip_list.c src/compress.c src/bloom_filter.c src/binary_hash_array.c src/lru.c src/queue.c external/xxhash.c)
else()
    add_library(tidesdb SHARED src/tidesdb.c src/block_manager.c src/skip_list.c src/compress.c src/bloom_filter.c src/binary_hash_array.c src/lru.c src/queue.c external/xxhash.c)
endif()

target_include_directories(tidesdb PRIVATE src)

# find OpenSSL for SHA1 checksums
find_package(OpenSSL REQUIRED)

# find compression libraries (use CONFIG mode on Windows with vcpkg)
if(WIN32)
    find_package(zstd CONFIG REQUIRED)
    find_package(Snappy CONFIG REQUIRED)
    find_package(lz4 CONFIG REQUIRED)
    find_package(PThreads4W REQUIRED)
endif()

if(APPLE AND CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64")
    # for apple silicon macs, homebrew installs packages in /opt/homebrew
    target_include_directories(tidesdb PUBLIC /opt/homebrew/include)
    target_link_directories(tidesdb PUBLIC /opt/homebrew/lib)
    # link against compression libraries for apple silicon
    target_link_libraries(tidesdb PUBLIC
            m           # math library
            lz4         # lz4 compression
            zstd        # zstandard compression
            snappy      # snappy compression
            pthread     # pthread library
            OpenSSL::Crypto  # openssl for SHA1
    )
elseif(APPLE)
    # for intel macs, homebrew typically installs in /usr/local
    target_include_directories(tidesdb PUBLIC /usr/local/include)
    target_link_directories(tidesdb PUBLIC /usr/local/lib)
    # link against compression libraries for intel mac
    target_link_libraries(tidesdb PUBLIC
            m           # math library
            lz4         # lz4 compression
            zstd        # zstandard compression
            snappy      # snappy compression
            pthread     # pthread library
            OpenSSL::Crypto  # openssl for SHA1
    )
elseif(WIN32)
    # for windows, link against compression libraries and pthreads
    target_link_libraries(tidesdb PUBLIC
            $<IF:$<TARGET_EXISTS:zstd::libzstd_shared>,zstd::libzstd_shared,zstd::libzstd_static>
            Snappy::snappy
            lz4::lz4
            PThreads4W::PThreads4W
            OpenSSL::Crypto
    )
else()
    # for linux and other unix systems
    target_link_libraries(tidesdb PUBLIC
            zstd
            snappy
            lz4
            pthread
            OpenSSL::Crypto
    )
    find_library(MATH_LIBRARY m)
    if(MATH_LIBRARY)
        target_link_libraries(tidesdb PUBLIC ${MATH_LIBRARY})
    endif()
endif()

install(TARGETS tidesdb
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)

install(DIRECTORY src/ DESTINATION include/tidesdb FILES_MATCHING PATTERN "*.h")
install(FILES external/xxhash.h DESTINATION include/tidesdb)

if(TIDESDB_BUILD_TESTS) # enable building tests and benchmarks
    enable_testing()

    add_executable(block_manager_tests test/block_manager__tests.c)
    add_executable(skip_list_tests test/skip_list__tests.c)
    add_executable(compress_tests test/compress__tests.c)
    add_executable(bloom_filter_tests test/bloom_filter__tests.c)
    add_executable(binary_hash_array_tests test/binary_hash_array__tests.c)
    add_executable(lru_tests test/lru__tests.c)
    add_executable(queue_tests test/queue__tests.c)
    add_executable(tidesdb_tests test/tidesdb__tests.c)
    add_executable(tidesdb_bench bench/tidesdb__bench.c)

    # add include and link directories for test executables
    foreach(test_target block_manager_tests skip_list_tests compress_tests bloom_filter_tests binary_hash_array_tests lru_tests queue_tests tidesdb_tests tidesdb_bench)
        target_link_libraries(${test_target} PRIVATE tidesdb)
        target_include_directories(${test_target} PRIVATE external)
    endforeach()

    add_test(NAME block_manager_tests COMMAND block_manager_tests)
    add_test(NAME skip_list_tests COMMAND skip_list_tests)
    add_test(NAME compress_tests COMMAND compress_tests)
    add_test(NAME bloom_filter_tests COMMAND bloom_filter_tests)
    add_test(NAME binary_hash_array_tests COMMAND binary_hash_array_tests)
    add_test(NAME lru_tests COMMAND lru_tests)
    add_test(NAME queue_tests COMMAND queue_tests)
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
            foreach(test_target block_manager_tests skip_list_tests compress_tests bloom_filter_tests binary_hash_array_tests lru_tests queue_tests tidesdb_tests tidesdb_bench)
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