#include <gtest/gtest.h>

#include <memory>

#include "../libtidesdb.hpp"

// Test fixture for SSTableIterator tests
class SSTableIteratorTest : public ::testing::Test {
   protected:
    std::string testFileName = "test_sstable_iterator_file.dat";

    void SetUp() override {
        // Remove the test file if it exists
        std::remove(testFileName.c_str());
    }

    void TearDown() override {
        // Remove the test file after each test
        std::remove(testFileName.c_str());
    }
};

TEST_F(SSTableIteratorTest, WriteAndReadMultiplePages) {
    auto pager = std::make_shared<TidesDB::Pager>(testFileName,
                                                  std::ios::out | std::ios::in | std::ios::binary);

    KeyValue kv1;

    kv1.set_key("key1");
    kv1.set_value("value1");

    KeyValue kv2;

    kv2.set_key("key2");
    kv2.set_value("value2");

    KeyValue kv3;

    kv3.set_key("key3");
    kv3.set_value("value3");

    pager->Write(TidesDB::serialize(kv1));
    pager->Write(TidesDB::serialize(kv2));
    pager->Write(TidesDB::serialize(kv3));

    TidesDB::SSTableIterator iterator(pager);

    std::vector<KeyValue> expectedData = {kv1, kv2, kv3};
    int index = 0;

    while (iterator.Ok()) {
        auto keyValue = iterator.Next();
        ASSERT_TRUE(keyValue.has_value());
        EXPECT_EQ(keyValue->key(), expectedData[index].key());
        EXPECT_EQ(keyValue->value(), expectedData[index].value());
        index++;
    }

    EXPECT_EQ(index, expectedData.size());
}