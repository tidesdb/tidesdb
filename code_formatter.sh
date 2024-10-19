#!/bin/bash

EXCLUDE_DIRS="proto\|ffi"

# Find all files except those in the excluded directories and run clang-format
find . -type f -name "*.cpp" -o -name "*.h" | grep -v "$EXCLUDE_DIRS" | xargs clang-format -i