cmake_minimum_required(VERSION 3.29)
project(tidesdb)

set(CMAKE_CXX_STANDARD 20)

# Find Protobuf package
find_package(Protobuf REQUIRED)

# Find Zstandard package
find_package(zstd REQUIRED)

# Include the generated protobuf headers
include_directories(${Protobuf_INCLUDE_DIRS})

# Specify paths for generated protobuf source and header files
set(PROTO_SRC
        proto/kv.pb.cc
        proto/operation.pb.cc
)

set(PROTO_HDR
        proto/kv.pb.h
        proto/operation.pb.h
)

# Add the library and link with Protobuf and Zstandard
add_library(tidesdb STATIC libtidesdb.cpp ${PROTO_SRC})

target_link_libraries(tidesdb PRIVATE
        ${Protobuf_LIBRARIES}
        zstd::libzstd
)

target_include_directories(tidesdb PRIVATE ${Protobuf_INCLUDE_DIRS})

# Add Google Test
enable_testing()
find_package(GTest REQUIRED)
include_directories(${GTest_INCLUDE_DIRS})

# Collect all test source files
file(GLOB TEST_SRC "tests/*.cpp")

# Define the test executable
add_executable(runTests ${TEST_SRC}
        tests/convert_to_char_vector.cpp
        tests/run_tests.cpp
        tests/compress_zstd.cpp
        tests/decompres_zstd.cpp
        tests/serialize.cpp
        tests/deserialize.cpp
        tests/serialize_operation.cpp
        tests/deserialize_operation.cpp
        tests/avl.cpp
        tests/avl_concurrent.cpp
        tests/avl_ttl.cpp
        tests/lsmt.cpp
        tests/lsmt_flush.cpp
        tests/lsmt_flush_concurrent.cpp
        tests/lsmt_compact.cpp
        tests/lsmt_compact_concurrent.cpp
        tests/pager.cpp
        tests/pager_overflows.cpp
        tests/sstable.cpp
        tests/sstable_iterator.cpp
        tests/wal.cpp
        tests/recovery.cpp
        tests/transactions.cpp
        tests/transactions_concurrent.cpp
        tests/equi_functions.cpp
        tests/range_functions.cpp
        tests/put_batch.cpp
        tests/delete_batch.cpp
)

# Link the test executable with Google Test and tidesdb
target_link_libraries(runTests PRIVATE
        GTest::GTest
        GTest::Main
        tidesdb
)

# Add tests
add_test(NAME runTests COMMAND runTests)