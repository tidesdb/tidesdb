#!/bin/bash

EXCLUDE_DIRS="external\|cmake-build-debug\|.idea|build|cmake"

find . -type f -name "*.c" -o -name "*.h" | grep -v "$EXCLUDE_DIRS" | xargs clang-format -i