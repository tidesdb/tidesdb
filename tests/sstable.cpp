#include <gtest/gtest.h>

#include <memory>

#include "../libtidesdb.hpp"

// Test fixture for SSTable tests
class SSTableTest : public ::testing::Test {
   protected:
    std::string testFileName = "test_sstable_file.dat";

    void SetUp() override {
        // Remove the test file if it exists
        std::remove(testFileName.c_str());
    }

    void TearDown() override {
        // Remove the test file after each test
        std::remove(testFileName.c_str());
    }
};

TEST_F(SSTableTest, ConstructorInitializesCorrectly) {
    auto pager = std::make_shared<TidesDB::Pager>(testFileName, std::ios::out | std::ios::binary);
    TidesDB::SSTable sstable(pager);

    EXPECT_EQ(sstable.pager, pager);
    EXPECT_TRUE(sstable.minKey.empty());
    EXPECT_TRUE(sstable.maxKey.empty());
}

TEST_F(SSTableTest, GetFilePathReturnsCorrectPath) {
    auto pager = std::make_shared<TidesDB::Pager>(testFileName, std::ios::out | std::ios::binary);
    TidesDB::SSTable sstable(pager);

    EXPECT_EQ(sstable.GetFilePath(), testFileName);
}