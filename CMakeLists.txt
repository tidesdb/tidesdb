# build instructions--
# cmake -S . -B build
# cmake --build build
# cmake --install build
cmake_minimum_required(VERSION 3.25)
project(tidesdb C)

set(CMAKE_C_STANDARD 23)
set(PROJECT_VERSION 0.7.0) # TidesDB v0.7.0b

# when building for production releases, you/we want to disable all warnings and sanitizers
option(TIDESDB_WITH_SANITIZER "build with sanitizer in tidesdb" ON)
option(TIDESDB_BUILD_TESTS "enable building tests in tidesdb" ON)

# for development, we want to enable all warnings and sanitizers
if(TIDESDB_WITH_SANITIZER)
        if(WIN32)
                # debug flags for windows, this is mainly for visual studio users
                # if not using visual studio 2019+ comment out the below lines
                add_compile_options(/W4 /fsanitize=address /fsanitize=undefined)
                add_link_options(/fsanitize=address /fsanitize=undefined)
        else()
                add_compile_options(-Wextra -Wall -fsanitize=address,undefined)
                add_link_options(-fsanitize=address,undefined)
        endif()
endif()

add_library(tidesdb SHARED src/tidesdb.c src/err.c src/block_manager.c src/skip_list.c src/compress.c src/bloom_filter.c src/hash_table.c src/binary_hash_array.c src/log.c external/xxhash.c)

target_include_directories(tidesdb PRIVATE src)
if(APPLE AND CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64")
        # for apple silicon macs, homebrew installs packages in /opt/homebrew
        target_include_directories(tidesdb PUBLIC /opt/homebrew/include)
        target_link_directories(tidesdb PUBLIC /opt/homebrew/lib)
        # link against compression libraries for apple silicon
        target_link_libraries(tidesdb PUBLIC
                m       # math library
                lz4     # lz4 compression
                zstd    # zstandard compression
                snappy  # snappy compression
                pthread # pthread library
        )
elseif(APPLE)
        # for intel macs, homebrew typically installs in /usr/local
        target_include_directories(tidesdb PUBLIC /usr/local/include)
        target_link_directories(tidesdb PUBLIC /usr/local/lib)
        # link against compression libraries for intel mac
        target_link_libraries(tidesdb PUBLIC
                m       # math library
                lz4     # lz4 compression
                zstd    # zstandard compression
                snappy  # snappy compression
                pthread # pthread library
        )
else()
        target_link_libraries(tidesdb PUBLIC zstd snappy lz4 pthread)
        find_library(MATH_LIBRARY m)
        if(MATH_LIBRARY)
                target_link_libraries(tidesdb PUBLIC ${MATH_LIBRARY})
        endif()
endif()

install(TARGETS tidesdb
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)

install(FILES src/tidesdb.h src/err.h src/block_manager.h src/skip_list.h src/hash_table.h src/compress.h src/bloom_filter.h src/compat.h src/log.h src/binary_hash_array.h DESTINATION include)

if(TIDESDB_BUILD_TESTS) # enable building tests and benchmarks
        enable_testing()

        add_executable(err_tests test/err__tests.c)
        add_executable(block_manager_tests test/block_manager__tests.c)
        add_executable(skip_list_tests test/skip_list__tests.c)
        add_executable(hash_table_tests test/hash_table__tests.c)
        add_executable(compress_tests test/compress__tests.c)
        add_executable(bloom_filter_tests test/bloom_filter__tests.c)
        add_executable(log_tests test/log__tests.c)
        add_executable(binary_hash_array_tests test/binary_hash_array__tests.c)
        add_executable(tidesdb_tests test/tidesdb__tests.c)
        add_executable(tidesdb_bench bench/tidesdb__bench.c)

        # add include and link directories for test executables
        foreach(test_target err_tests block_manager_tests skip_list_tests hash_table_tests compress_tests bloom_filter_tests log_tests binary_hash_array_tests tidesdb_tests tidesdb_bench)
                target_link_libraries(${test_target} PRIVATE tidesdb)
        endforeach()

        add_test(NAME err_tests COMMAND err_tests)
        add_test(NAME block_manager_tests COMMAND block_manager_tests)
        add_test(NAME skip_list_tests COMMAND skip_list_tests)
        add_test(NAME hash_table_tests COMMAND hash_table_tests)
        add_test(NAME compress_tests COMMAND compress_tests)
        add_test(NAME bloom_filter_tests COMMAND bloom_filter_tests)
        add_test(NAME binary_hash_array_tests COMMAND binary_hash_array_tests)
        add_test(NAME log_tests COMMAND log_tests)
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
