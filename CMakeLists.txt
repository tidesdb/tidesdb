## cmake build instructions unix
# rm -rf build && cmake -S . -B build
# cmake --build build
# cmake --install build

## cmake build instructions windows
# rmdir /s /q build && cmake -S . -B build
# cmake --build build
# cmake --install build
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
    if(WIN32)
        # debug flags for windows
        # MSVC ASAN can be unstable, so we only enable warnings for CI
        add_compile_options(/W4 /std:c11)
    else()
        add_compile_options(-Wextra -Wall -fsanitize=address,undefined)
        add_link_options(-fsanitize=address,undefined)
    endif()
else()
    if(WIN32)
        # ensure C11 support is enabled even without sanitizers
        add_compile_options(/std:c11)
    endif()
endif()

include_directories(external) # for external libraries linking internally

add_library(tidesdb src/tidesdb.c src/block_manager.c src/skip_list.c src/compress.c src/bloom_filter.c src/binary_hash_array.c external/xxhash.c)

target_include_directories(tidesdb PRIVATE src)

# find OpenSSL for SHA1 checksums
find_package(OpenSSL REQUIRED)

# find PThreads4W for Windows
if(WIN32)
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
            zstd
            snappy
            lz4
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
    add_executable(tidesdb_tests test/tidesdb__tests.c)
    add_executable(tidesdb_bench bench/tidesdb__bench.c)

    # add include and link directories for test executables
    foreach(test_target block_manager_tests skip_list_tests compress_tests bloom_filter_tests binary_hash_array_tests tidesdb_tests tidesdb_bench)
        target_link_libraries(${test_target} PRIVATE tidesdb)
        target_include_directories(${test_target} PRIVATE external)
    endforeach()

    add_test(NAME block_manager_tests COMMAND block_manager_tests)
    add_test(NAME skip_list_tests COMMAND skip_list_tests)
    add_test(NAME compress_tests COMMAND compress_tests)
    add_test(NAME bloom_filter_tests COMMAND bloom_filter_tests)
    add_test(NAME binary_hash_array_tests COMMAND binary_hash_array_tests)
    add_test(NAME tidesdb_tests COMMAND tidesdb_tests)
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