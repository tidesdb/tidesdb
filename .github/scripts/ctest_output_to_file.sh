#!/bin/sh
# runs one test for ctest with its output going to a file instead of ctest's pipe, then prints the
# file. a test writing straight into that pipe has parked for the whole timeout on NetBSD, its
# writer never returning from a write the reader had already taken, while the same binaries run
# clean with their output on a file. a file never makes a writer wait on another process.
# used as CMAKE_TEST_LAUNCHER, so ctest runs this with the test's own command line appended
out=$(mktemp "${TMPDIR:-/tmp}/tidesdb-test.XXXXXX") || exit 1
"$@" > "$out" 2>&1
rc=$?
cat "$out"
rm -f "$out"
exit $rc
