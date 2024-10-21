#include <gtest/gtest.h>

#include "../libtidesdb.hpp"  // Include the header where serialize is declared

// Test case for serialize
TEST(SerializeTest, HandlesEmptyKeyValue) {
    KeyValue kv;
    EXPECT_THROW({ std::vector<uint8_t> output = TidesDB::serialize(kv); },
                 TidesDB::TidesDBException);
}

TEST(SerializeTest, HandlesNonEmptyKeyValue) {
    KeyValue kv;
    kv.set_key("test_key");
    kv.set_value("test_value");
    std::vector<uint8_t> output = TidesDB::serialize(kv);
    EXPECT_FALSE(output.empty());
}

TEST(SerializeTest, HandlesLargeKeyValue) {
    KeyValue kv;
    kv.set_key(std::string(1000, 'k'));    // Large key of 1000 'k' characters
    kv.set_value(std::string(1000, 'v'));  // Large value of 1000 'v' characters
    std::vector<uint8_t> output = TidesDB::serialize(kv);
    EXPECT_FALSE(output.empty());
}
