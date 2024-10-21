#include <gtest/gtest.h>

#include "../libtidesdb.hpp"  // Include the header where decompressZstd is declared

// Test case for decompressZstd
TEST(DecompressZstdTest, HandlesEmptyInput) {
    std::vector<uint8_t> input;
    std::vector<uint8_t> output = TidesDB::decompressZstd(input);
    EXPECT_TRUE(output.empty());
}

TEST(DecompressZstdTest, HandlesValidCompressedInput) {
    std::vector<uint8_t> input = {'a', 'b', 'c'};
    std::vector<uint8_t> compressed = TidesDB::compressZstd(input);
    std::vector<uint8_t> output = TidesDB::decompressZstd(compressed);
    EXPECT_EQ(output, input);
}

TEST(DecompressZstdTest, HandlesInvalidCompressedInput) {
    std::vector<uint8_t> input = {'a', 'b', 'c'};
    EXPECT_THROW(TidesDB::decompressZstd(input), TidesDB::TidesDBException);
}
