#!/bin/bash

# Define the folder to exclude
EXCLUDE_DIR="proto"

# Find all files except those in the excluded directory and run clang-format
find . -type f -name "*.cpp" -o -name "*.h" | grep -v "$EXCLUDE_DIR" | xargs clang-format -i