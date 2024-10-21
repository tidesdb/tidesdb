#include <gtest/gtest.h>

#include "../libtidesdb.hpp"  // Include the header where compressZstd is declared

// Test case for compressZstd
TEST(CompressZstdTest, HandlesEmptyInput) {
    std::vector<uint8_t> input;
    std::vector<uint8_t> output = TidesDB::compressZstd(input);
    EXPECT_TRUE(output.empty());
}

TEST(CompressZstdTest, HandlesNonEmptyInput) {
    std::vector<uint8_t> input = {'a', 'b', 'c'};
    std::vector<uint8_t> output = TidesDB::compressZstd(input);
    EXPECT_FALSE(output.empty());
}

TEST(CompressZstdTest, HandlesLargeInput) {
    std::vector<uint8_t> input(1000, 'a');  // Large input of 1000 'a' characters
    std::vector<uint8_t> output = TidesDB::compressZstd(input);
    EXPECT_FALSE(output.empty());
    EXPECT_LT(output.size(), input.size());  // Compressed size should be less than input size
}
