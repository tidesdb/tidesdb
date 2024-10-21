#include <gtest/gtest.h>

#include "../libtidesdb.hpp"  // Include the header where deserialize is declared

// Test case for deserialize
TEST(DeserializeTest, HandlesEmptyBuffer) {
    std::vector<uint8_t> buffer;
    EXPECT_THROW({ KeyValue kv = TidesDB::deserialize(buffer); }, TidesDB::TidesDBException);
}

TEST(DeserializeTest, HandlesValidBuffer) {
    KeyValue kv;
    kv.set_key("test_key");
    kv.set_value("test_value");
    std::vector<uint8_t> buffer = TidesDB::serialize(kv);
    KeyValue deserializedKv = TidesDB::deserialize(buffer);
    EXPECT_EQ(deserializedKv.key(), kv.key());
    EXPECT_EQ(deserializedKv.value(), kv.value());
}
