#!/bin/bash
set -euo pipefail

# Before submitting a PR, run this script to format the source code.

find . \
  \( -path "./external" \
     -o -path "./cmake-build-debug" \
     -o -path "./cmake-build-release" \
     -o -path "./.idea" \
     -o -path "./build" \
     -o -path "./cmake" \) -prune \
  -o -type f \( -name "*.c" -o -name "*.h" \) -print0 \
| xargs -0 clang-format -i
