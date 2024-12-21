# build instructions--
# cmake -S . -B build
# cmake --build build
# cmake --install build
cmake_minimum_required(VERSION 3.25)
project(tidesdb C)

set(CMAKE_C_STANDARD 23)
set(PROJECT_VERSION 0.3.0) # TidesDB v0.3.0b

option(TIDESDB_WITH_SANITIZER "build with sanitizer in tidesdb" ON)
option(TIDESDB_BUILD_TESTS "enable building tests in tidesdb" ON)

IF (WIN32)
        # install via vcpkg
        find_package(zstd REQUIRED)
        find_package(snappy REQUIRED)
        find_package(lz4 REQUIRED)
ENDIF() # on unix systems find_package will cause issues on make process usually looking for the packages even though installed apt-get or brew say.


# for development, we want to enable all warnings and sanitizers
if(TIDESDB_WITH_SANITIZER)
        add_compile_options(-Wextra -Wall -fsanitize=address,undefined)
        add_link_options(-fsanitize=address,undefined)
endif()

add_library(tidesdb SHARED src/tidesdb.c src/err.c src/block_manager.c src/skip_list.c src/compress.c src/bloom_filter.c src/hash_table.c src/compat.h)

target_include_directories(tidesdb PRIVATE src)
if(APPLE AND CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64")
        # For Apple Silicon Macs, Homebrew installs packages in /opt/homebrew
        target_include_directories(tidesdb PRIVATE /opt/homebrew/include)
        target_link_directories(tidesdb PRIVATE /opt/homebrew/lib)
        # Link against compression libraries for Apple Silicon
        target_link_libraries(tidesdb PRIVATE
                m       # math library
                lz4     # LZ4 compression
                zstd    # Zstandard compression
                snappy  # Snappy compression
        )
elseif(APPLE)
        # For Intel Macs, Homebrew typically installs in /usr/local
        target_include_directories(tidesdb PRIVATE /usr/local/include)
        target_link_directories(tidesdb PRIVATE /usr/local/lib)
        # Link against compression libraries for Intel Mac
        target_link_libraries(tidesdb PRIVATE
                m       # math library
                lz4     # LZ4 compression
                zstd    # Zstandard compression
                snappy  # Snappy compression
        )
endif()
target_link_libraries(tidesdb PRIVATE zstd snappy lz4)
find_library(MATH_LIBRARY m)
if(MATH_LIBRARY)
    target_link_libraries(tidesdb PRIVATE ${MATH_LIBRARY})
endif()

install(TARGETS tidesdb
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)

install(FILES src/tidesdb.h src/err.h src/block_manager.h src/skip_list.h src/hash_table.h src/compress.h src/bloom_filter.h src/compat.h DESTINATION include)

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

        # Add include and link directories for test executables
        if(APPLE AND CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64")
                foreach(test_target err_tests block_manager_tests skip_list_tests hash_table_tests compress_tests bloom_filter_tests tidesdb_tests tidesdb_bench)
                        target_include_directories(${test_target} PRIVATE /opt/homebrew/include)
                        target_link_directories(${test_target} PRIVATE /opt/homebrew/lib)
                        target_link_libraries(${test_target} tidesdb m zstd snappy lz4)
                endforeach()
        elseif(APPLE)
                foreach(test_target err_tests block_manager_tests skip_list_tests hash_table_tests compress_tests bloom_filter_tests tidesdb_tests tidesdb_bench)
                        target_include_directories(${test_target} PRIVATE /usr/local/include)
                        target_link_directories(${test_target} PRIVATE /usr/local/lib)
                        target_link_libraries(${test_target} tidesdb m zstd snappy lz4)
                endforeach()
        else()
                foreach(test_target err_tests block_manager_tests skip_list_tests hash_table_tests compress_tests bloom_filter_tests tidesdb_tests tidesdb_bench)
                        target_link_libraries(${test_target} tidesdb m zstd snappy lz4)
                endforeach()
        endif()

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
