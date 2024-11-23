# cmake -S . -B build
# cmake --build build
# cmake --install build
cmake_minimum_required(VERSION 3.25)
project(tidesdb C)

set(CMAKE_C_STANDARD 23)
set(PROJECT_VERSION 1.0.0)

find_package(zstd REQUIRED)

add_library(xxhash STATIC external/xxhash.c)
add_library(tidesdb SHARED src/tidesdb.c src/tidesdb.h src/err.c src/err.h src/pager.c src/pager.h src/skiplist.c src/skiplist.h src/queue.c src/queue.h src/bloomfilter.c src/bloomfilter.h src/serializable_structures.h src/serialize.c src/serialize.h)

install(TARGETS tidesdb
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)

install(FILES src/tidesdb.h src/err.h src/pager.h src/skiplist.h src/queue.h src/bloomfilter.h external/xxhash.h src/serializable_structures.h src/serialize.h DESTINATION include)
enable_testing()

add_executable(err_tests test/err__tests.c)
add_executable(pager_tests test/pager__tests.c)
add_executable(skiplist_tests test/skiplist__tests.c)
add_executable(queue_tests test/queue__tests.c)
add_executable(bloomfilter_tests test/bloomfilter__tests.c)
add_executable(serialize_tests test/serialize__tests.c)
add_executable(tidesdb_tests test/tidesdb__tests.c)

target_link_libraries(tidesdb xxhash zstd)
target_link_libraries(pager_tests tidesdb)
target_link_libraries(skiplist_tests tidesdb)
target_link_libraries(queue_tests tidesdb)
target_link_libraries(bloomfilter_tests tidesdb xxhash)
target_link_libraries(serialize_tests tidesdb)
target_link_libraries(tidesdb_tests tidesdb xxhash zstd)

add_test(NAME err_tests COMMAND err_tests)
add_test(NAME pager_tests COMMAND pager_tests)
add_test(NAME skiplist_tests COMMAND skiplist_tests)
add_test(NAME queue_tests COMMAND queue_tests)
add_test(NAME bloomfilter_tests COMMAND bloomfilter_tests)
add_test(NAME serialize_tests COMMAND serialize_tests)
add_test(NAME tidesdb_test COMMAND tidesdb_tests)

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
