#include <gtest/gtest.h>

#include "../libtidesdb.hpp"

TEST(BloomFilterTest, AddAndContains) {
    TidesDB::BloomFilter bloomFilter(1000, 3);

    std::vector<uint8_t> key1 = {1, 2, 3, 4};
    std::vector<uint8_t> key2 = {5, 6, 7, 8};

    bloomFilter.add(key1);

    EXPECT_TRUE(bloomFilter.contains(key1));
    EXPECT_FALSE(bloomFilter.contains(key2));
}

TEST(BloomFilterTest, MultipleKeys) {
    TidesDB::BloomFilter bloomFilter(1000, 3);

    std::vector<uint8_t> key1 = {1, 2, 3, 4};
    std::vector<uint8_t> key2 = {5, 6, 7, 8};
    std::vector<uint8_t> key3 = {9, 10, 11, 12};

    bloomFilter.add(key1);
    bloomFilter.add(key2);

    EXPECT_TRUE(bloomFilter.contains(key1));
    EXPECT_TRUE(bloomFilter.contains(key2));
    EXPECT_FALSE(bloomFilter.contains(key3));
}

TEST(BloomFilterTest, FalsePositives) {
    TidesDB::BloomFilter bloomFilter(1000, 3);

    std::vector<uint8_t> key1 = {1, 2, 3, 4};
    std::vector<uint8_t> key2 = {5, 6, 7, 8};

    bloomFilter.add(key1);

    // Since Bloom filters can have false positives, we cannot assert that key2 is definitely not in
    // the filter. Instead, we check that key1 is definitely in the filter.
    EXPECT_TRUE(bloomFilter.contains(key1));
}

TEST(BloomFilterTest, SerializeDeserialize) {
    TidesDB::BloomFilter bloomFilter(1000, 3);

    std::vector<uint8_t> key1 = {1, 2, 3, 4};
    std::vector<uint8_t> key2 = {5, 6, 7, 8};

    bloomFilter.add(key1);
    bloomFilter.add(key2);

    std::vector<uint8_t> serializedData = bloomFilter.serialize();
    TidesDB::BloomFilter deserializedBloomFilter =
        TidesDB::BloomFilter::deserialize(serializedData);

    EXPECT_TRUE(deserializedBloomFilter.contains(key1));
    EXPECT_TRUE(deserializedBloomFilter.contains(key2));
}

TEST(BloomFilterTest, SerializeEmptyFilter) {
    TidesDB::BloomFilter bloomFilter(1000, 3);

    std::vector<uint8_t> serializedData = bloomFilter.serialize();
    TidesDB::BloomFilter deserializedBloomFilter =
        TidesDB::BloomFilter::deserialize(serializedData);

    std::vector<uint8_t> key = {1, 2, 3, 4};
    EXPECT_FALSE(deserializedBloomFilter.contains(key));
}

TEST(BloomFilterTest, SerializePartialFilter) {
    TidesDB::BloomFilter bloomFilter(1000, 3);

    std::vector<uint8_t> key1 = {1, 2, 3, 4};
    std::vector<uint8_t> key2 = {5, 6, 7, 8};

    bloomFilter.add(key1);

    std::vector<uint8_t> serializedData = bloomFilter.serialize();
    TidesDB::BloomFilter deserializedBloomFilter =
        TidesDB::BloomFilter::deserialize(serializedData);

    EXPECT_TRUE(deserializedBloomFilter.contains(key1));
    EXPECT_FALSE(deserializedBloomFilter.contains(key2));
}