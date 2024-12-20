# build instructions--
# cmake -S . -B build
# cmake --build build
# cmake --install build
cmake_minimum_required(VERSION 3.25)
project(tidesdb C)

set(CMAKE_C_STANDARD 23)
set(PROJECT_VERSION 0.2.0) # TidesDB v0.2.0

option(TIDESDB_WITH_SANITIZER "build with sanitizer in tidesdb" ON)
option(TIDESDB_BUILD_TESTS "enable building tests in tidesdb" ON)

#find_package(zstd REQUIRED)
#find_package(snappy REQUIRED)
#find_package(lz4 REQUIRED)

# for development, we want to enable all warnings and sanitizers
if(TIDESDB_WITH_SANITIZER)
        add_compile_options(-Wextra -Wall -fsanitize=address,undefined)
        add_link_options(-fsanitize=address,undefined)
endif()

add_library(tidesdb SHARED src/tidesdb.c src/err.c src/block_manager.c src/skip_list.c src/compress.c src/bloom_filter.c src/hash_table.c src/compat.h)

target_include_directories(tidesdb PRIVATE src)

install(TARGETS tidesdb
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)

install(FILES src/tidesdb.h src/err.h src/block_manager.h src/skip_list.h src/compress.h src/bloom_filter.h src/compat.h DESTINATION include)

if(TIDESDB_BUILD_TESTS) # enable building tests and benchmarks
        enable_testing()

        add_executable(err_tests test/err__tests.c)
        add_executable(block_manager_tests test/block_manager__tests.c)
        add_executable(skip_list_tests test/skip_list__tests.c)
        add_executable(hash_table_tests test/hash_table__tests.c)
        add_executable(compress_tests test/compress__tests.c)
        add_executable(bloom_filter_tests test/bloom_filter__tests.c)
        add_executable(tidesdb_tests test/tidesdb__tests.c)
        add_executable(tidesdb_bench bench/tidesdb__bench.c)

        target_link_libraries(err_tests tidesdb m zstd snappy lz4)
        target_link_libraries(block_manager_tests tidesdb m zstd snappy lz4)
        target_link_libraries(skip_list_tests tidesdb m zstd snappy lz4)
        target_link_libraries(hash_table_tests tidesdb m zstd snappy lz4)
        target_link_libraries(compress_tests tidesdb m zstd snappy lz4)
        target_link_libraries(bloom_filter_tests tidesdb m zstd snappy lz4)
        target_link_libraries(tidesdb_tests tidesdb m zstd snappy lz4)
        target_link_libraries(tidesdb_bench tidesdb m zstd snappy lz4)

        add_test(NAME err_tests COMMAND err_tests)
        add_test(NAME block_manager_tests COMMAND block_manager_tests)
        add_test(NAME skip_list_tests COMMAND skip_list_tests)
        add_test(NAME hash_table_tests COMMAND hash_table_tests)
        add_test(NAME compress_tests COMMAND compress_tests)
        add_test(NAME bloom_filter_tests COMMAND bloom_filter_tests)
        add_test(NAME tidesdb_tests COMMAND tidesdb_tests)
        add_test(NAME tidesdb_bench COMMAND tidesdb_bench)
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