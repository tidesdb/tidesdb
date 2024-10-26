#include <gtest/gtest.h>

#include "../libtidesdb.hpp"

// Test case for ConvertToCharVector
TEST(ConvertToCharVectorTest, HandlesEmptyInput) {
    std::vector<uint8_t> input;
    std::vector<char> expected_output;
    EXPECT_EQ(TidesDB::ConvertToCharVector(input), expected_output);
}

TEST(ConvertToCharVectorTest, HandlesNonEmptyInput) {
    std::vector<uint8_t> input = {static_cast<uint8_t>('a'), static_cast<uint8_t>('b'),
                                  static_cast<uint8_t>('c')};
    std::vector<char> expected_output = {'a', 'b', 'c'};
    EXPECT_EQ(TidesDB::ConvertToCharVector(input), expected_output);
}

TEST(ConvertToCharVectorTest, HandlesSpecialCharacters) {
    std::vector<uint8_t> input = {static_cast<uint8_t>('\0'), static_cast<uint8_t>('\n'),
                                  static_cast<uint8_t>('\t')};
    std::vector<char> expected_output = {'\0', '\n', '\t'};
    EXPECT_EQ(TidesDB::ConvertToCharVector(input), expected_output);
}
