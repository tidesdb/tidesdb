# cmake -S . -B build
# cmake --build build
# cmake --install build
cmake_minimum_required(VERSION 3.25)
project(tidesdb C)

set(CMAKE_C_STANDARD 23)
set(PROJECT_VERSION 0.2.0) # TidesDB v0.2.0

#find_package(zstd REQUIRED)
#find_package(snappy REQUIRED)
#find_package(lz4 REQUIRED)

# For development, we want to enable all warnings and sanitizers
add_compile_options(-Wextra -Wall -fsanitize=address,undefined)
add_link_options(-fsanitize=address,undefined)

add_library(tidesdb SHARED src/tidesdb.c src/tidesdb.h src/err.c src/err.h src/block_manager.c src/block_manager.h src/skip_list.c src/skip_list.h src/compress.c src/compress.h src/bloom_filter.c src/block_manager.h)

install(TARGETS tidesdb
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)

install(FILES src/tidesdb.c src/tidesdb.h src/err.c src/err.h src/block_manager.c src/block_manager.h src/skip_list.c src/skip_list.h src/compress.c src/compress.h src/bloom_filter.c src/bloom_filter.h DESTINATION include)
enable_testing()

add_executable(err_tests test/err__tests.c)
add_executable(block_manager_tests test/block_manager__tests.c)
add_executable(skip_list_tests test/skip_list__tests.c)
add_executable(compress_tests test/compress__tests.c)
add_executable(bloom_filter_tests test/bloom_filter__tests.c)
add_executable(tidesdb_tests test/tidesdb__tests.c)

target_link_libraries(err_tests tidesdb m zstd snappy lz4)
target_link_libraries(block_manager_tests tidesdb m zstd snappy lz4)
target_link_libraries(skip_list_tests tidesdb m zstd snappy lz4)
target_link_libraries(compress_tests tidesdb m zstd snappy lz4)
target_link_libraries(bloom_filter_tests tidesdb m zstd snappy lz4)
target_link_libraries(tidesdb_tests tidesdb m zstd snappy lz4)

add_test(NAME err_tests COMMAND err_tests)
add_test(NAME block_manager_tests COMMAND block_manager_tests)
add_test(NAME skip_list_tests COMMAND skip_list_tests)
add_test(NAME compress_tests COMMAND compress_tests)
add_test(NAME bloom_filter_tests COMMAND bloom_filter_tests)
add_test(NAME tidesdb_tests COMMAND tidesdb_tests)

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