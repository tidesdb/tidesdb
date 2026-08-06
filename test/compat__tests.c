/**
 *
 * Copyright (C) TidesDB
 *
 * Original Author: Alex Gaetano Padula
 *
 * Licensed under the Mozilla Public License, v. 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.mozilla.org/en-US/MPL/2.0/
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

static void test_cgroup_memory_value_parser(void)
{
    size_t value = 0;
    ASSERT_EQ(tdb_parse_cgroup_memory_value("  16777216\n", &value), TDB_CGROUP_MEMORY_FINITE);
    ASSERT_EQ(value, (size_t)16777216);
    ASSERT_EQ(tdb_parse_cgroup_memory_value("max\n", &value), TDB_CGROUP_MEMORY_UNLIMITED);
    ASSERT_EQ(tdb_parse_cgroup_memory_value("-1", &value), TDB_CGROUP_MEMORY_INVALID);
    ASSERT_EQ(tdb_parse_cgroup_memory_value("12 MB", &value), TDB_CGROUP_MEMORY_INVALID);
    ASSERT_EQ(tdb_parse_cgroup_memory_value("18446744073709551616", &value),
              TDB_CGROUP_MEMORY_INVALID);
}

static void test_cgroup_v2_path_parser(void)
{
    const char contents[] = "7:cpu:/legacy\n0::/container/test/machine1\n";
    char group[128];
    ASSERT_EQ(tdb_parse_cgroup_v2_path(contents, group, sizeof(group)), 0);
    ASSERT_EQ(strcmp(group, "/container/test/machine1"), 0);
}

static void test_cgroup2_mountinfo_resolution(void)
{
    const char mountinfo[] =
        "31 25 0:27 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n"
        "42 25 0:31 /machine1 /run/cgroup\\040two rw,nosuid,nodev - cgroup2 cgroup rw\n";
    char root[128];
    char mountpoint[128];
    ASSERT_EQ(
        tdb_parse_cgroup2_mountinfo(mountinfo, root, sizeof(root), mountpoint, sizeof(mountpoint)),
        0);
    ASSERT_EQ(strcmp(root, "/machine1"), 0);
    ASSERT_EQ(strcmp(mountpoint, "/run/cgroup two"), 0);

    char path[256];
    ASSERT_EQ(tdb_resolve_cgroup2_directory(mountpoint, root, "/machine1/prodigy-runtime", path,
                                            sizeof(path)),
              0);
    ASSERT_EQ(strcmp(path, "/run/cgroup two/prodigy-runtime"), 0);
    ASSERT_EQ(
        tdb_resolve_cgroup2_directory(mountpoint, root, "/prodigy-runtime", path, sizeof(path)), 0);
    ASSERT_EQ(strcmp(path, "/run/cgroup two/prodigy-runtime"), 0);
    ASSERT_EQ(tdb_resolve_cgroup2_directory(mountpoint, root, "/", path, sizeof(path)), 0);
    ASSERT_EQ(strcmp(path, "/run/cgroup two"), 0);

    const char host_mountinfo[] =
        "42 25 0:31 / /sys/fs/cgroup rw,nosuid,nodev - cgroup2 cgroup rw\n";
    ASSERT_EQ(tdb_parse_cgroup2_mountinfo(host_mountinfo, root, sizeof(root), mountpoint,
                                          sizeof(mountpoint)),
              0);
    ASSERT_EQ(
        tdb_resolve_cgroup2_directory(mountpoint, root, "/container/test", path, sizeof(path)), 0);
    ASSERT_EQ(strcmp(path, "/sys/fs/cgroup/container/test"), 0);
    ASSERT_EQ(tdb_resolve_cgroup2_directory("/", root, "/container/test", path, sizeof(path)), 0);
    ASSERT_EQ(strcmp(path, "/container/test"), 0);
}

static void test_cgroup_memory_selection(void)
{
    ASSERT_EQ(tdb_cgroup_effective_total(3200, TDB_CGROUP_MEMORY_FINITE, 1600), (size_t)1600);
    ASSERT_EQ(tdb_cgroup_effective_total(3200, TDB_CGROUP_MEMORY_FINITE, 6400), (size_t)3200);
    ASSERT_EQ(tdb_cgroup_effective_total(3200, TDB_CGROUP_MEMORY_UNLIMITED, 0), (size_t)3200);

    ASSERT_EQ(tdb_cgroup_effective_available(2400, TDB_CGROUP_MEMORY_FINITE,
                                             TDB_CGROUP_MEMORY_FINITE, 1200),
              (size_t)1200);
    ASSERT_EQ(tdb_cgroup_effective_available(800, TDB_CGROUP_MEMORY_FINITE,
                                             TDB_CGROUP_MEMORY_FINITE, 1200),
              (size_t)800);
    ASSERT_EQ(
        tdb_cgroup_effective_available(2400, TDB_CGROUP_MEMORY_FINITE, TDB_CGROUP_MEMORY_FINITE, 0),
        (size_t)0);
    ASSERT_EQ(tdb_cgroup_effective_available(2400, TDB_CGROUP_MEMORY_FINITE,
                                             TDB_CGROUP_MEMORY_INVALID, 0),
              (size_t)0);
    ASSERT_EQ(tdb_cgroup_effective_available(2400, TDB_CGROUP_MEMORY_UNLIMITED,
                                             TDB_CGROUP_MEMORY_UNLIMITED, 0),
              (size_t)2400);
}

static void write_memory_value(const char *path, const char *value)
{
    FILE *file = fopen(path, "w");
    ASSERT_TRUE(file != NULL);
    ASSERT_TRUE(fputs(value, file) >= 0);
    ASSERT_EQ(fclose(file), 0);
}

static void test_cgroup_memory_ancestor_bounds(void)
{
    const char *root = "./test_cgroup_memory";
    (void)remove_directory(root);
    ASSERT_EQ(mkdir(root, 0755), 0);
    ASSERT_EQ(mkdir("./test_cgroup_memory/machine1", 0755), 0);
    ASSERT_EQ(mkdir("./test_cgroup_memory/machine1/prodigy-runtime", 0755), 0);

    write_memory_value("./test_cgroup_memory/memory.max", "max\n");
    write_memory_value("./test_cgroup_memory/machine1/memory.max", "1600\n");
    write_memory_value("./test_cgroup_memory/machine1/memory.current", "400\n");
    write_memory_value("./test_cgroup_memory/machine1/prodigy-runtime/memory.max", "max\n");

    tdb_cgroup_memory_bounds_t bounds;
    ASSERT_EQ(
        tdb_cgroup_memory_bounds_at(root, "./test_cgroup_memory/machine1/prodigy-runtime", &bounds),
        0);
    ASSERT_EQ(bounds.limit_state, TDB_CGROUP_MEMORY_FINITE);
    ASSERT_EQ(bounds.limit, (size_t)1600);
    ASSERT_EQ(bounds.available_state, TDB_CGROUP_MEMORY_FINITE);
    ASSERT_EQ(bounds.available, (size_t)1200);

    ASSERT_EQ(remove("./test_cgroup_memory/machine1/memory.current"), 0);
    ASSERT_EQ(
        tdb_cgroup_memory_bounds_at(root, "./test_cgroup_memory/machine1/prodigy-runtime", &bounds),
        0);
    ASSERT_EQ(bounds.limit_state, TDB_CGROUP_MEMORY_FINITE);
    ASSERT_EQ(bounds.limit, (size_t)1600);
    ASSERT_EQ(bounds.available_state, TDB_CGROUP_MEMORY_INVALID);
    ASSERT_EQ(tdb_cgroup_effective_available(2400, bounds.limit_state, bounds.available_state,
                                             bounds.available),
              (size_t)0);

    write_memory_value("./test_cgroup_memory/machine1/memory.current", "not-a-number\n");
    ASSERT_EQ(
        tdb_cgroup_memory_bounds_at(root, "./test_cgroup_memory/machine1/prodigy-runtime", &bounds),
        0);
    ASSERT_EQ(bounds.limit_state, TDB_CGROUP_MEMORY_FINITE);
    ASSERT_EQ(bounds.available_state, TDB_CGROUP_MEMORY_INVALID);

    ASSERT_EQ(remove_directory(root), 0);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_cgroup_memory_value_parser, tests_passed);
    RUN_TEST(test_cgroup_v2_path_parser, tests_passed);
    RUN_TEST(test_cgroup2_mountinfo_resolution, tests_passed);
    RUN_TEST(test_cgroup_memory_selection, tests_passed);
    RUN_TEST(test_cgroup_memory_ancestor_bounds, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed == 0 ? 0 : 1;
}
