#include <gtest/gtest.h>

#include "../libtidesdb.hpp"

// Runs all the tests in the TidesDB test suite
int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}