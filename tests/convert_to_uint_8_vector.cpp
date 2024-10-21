#include <gtest/gtest.h>

#include "../libtidesdb.hpp"  // Include the header where ConvertToUint8Vector is declared

// Test case for ConvertToUint8Vector
TEST(ConvertToUint8VectorTest, HandlesEmptyInput) {
    std::vector<char> input;
    std::vector<uint8_t> expected_output;
    EXPECT_EQ(TidesDB::ConvertToUint8Vector(input), expected_output);
}

TEST(ConvertToUint8VectorTest, HandlesNonEmptyInput) {
    std::vector<char> input = {'a', 'b', 'c'};
    std::vector<uint8_t> expected_output = {static_cast<uint8_t>('a'), static_cast<uint8_t>('b'),
                                            static_cast<uint8_t>('c')};
    EXPECT_EQ(TidesDB::ConvertToUint8Vector(input), expected_output);
}

TEST(ConvertToUint8VectorTest, HandlesSpecialCharacters) {
    std::vector<char> input = {'\0', '\n', '\t'};
    std::vector<uint8_t> expected_output = {static_cast<uint8_t>('\0'), static_cast<uint8_t>('\n'),
                                            static_cast<uint8_t>('\t')};
    EXPECT_EQ(TidesDB::ConvertToUint8Vector(input), expected_output);
}
