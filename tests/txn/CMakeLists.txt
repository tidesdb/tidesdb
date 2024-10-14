cmake_minimum_required(VERSION 3.29)
project(tidesdb)

set(CMAKE_CXX_STANDARD 20)

# Find Protobuf package
find_package(Protobuf REQUIRED)

# Include the generated protobuf headers
include_directories(${Protobuf_INCLUDE_DIRS})

# Add the generated protobuf source files
# protoc --cpp_out=. operation.proto
# protoc --cpp_out=. kv.proto
set(PROTO_SRC ../../kv.pb.cc ../../operation.pb.cc)
set(PROTO_HDR ../../kv.pb.h ../../operation.pb.h)

add_executable(tidesdb main.cpp ../../library.cpp ${PROTO_SRC})

# Link the protobuf library
target_link_libraries(tidesdb ${Protobuf_LIBRARIES})