#include <gtest/gtest.h>

#include <fstream>
#include <vector>

#include "../libtidesdb.hpp"

// Test fixture for Pager tests
class PagerTest : public ::testing::Test {
   protected:
    std::string testFileName = "test_pager_file.dat";

    void SetUp() override {
        // Remove the test file if it exists
        std::remove(testFileName.c_str());
    }

    void TearDown() override {
        // Remove the test file after each test
        std::remove(testFileName.c_str());
    }
};

TEST_F(PagerTest, ConstructorOpensFile) {
    TidesDB::Pager pager(testFileName, std::ios::out | std::ios::binary);
    EXPECT_TRUE(pager.GetFile().is_open());
}

TEST_F(PagerTest, WriteAndReadPage) {
    TidesDB::Pager pager(testFileName, std::ios::out | std::ios::in | std::ios::binary);
    std::vector<uint8_t> data = {'h', 'e', 'l', 'l', 'o'};
    int64_t pageNumber = pager.Write(data);

    std::vector<uint8_t> readData = pager.Read(pageNumber);
    EXPECT_EQ(data, readData);
}

TEST_F(PagerTest, CloseFile) {
    TidesDB::Pager pager(testFileName, std::ios::out | std::ios::binary);
    EXPECT_TRUE(pager.GetFile().is_open());
    EXPECT_TRUE(pager.Close());
    EXPECT_FALSE(pager.GetFile().is_open());
}

TEST_F(PagerTest, PagesCount) {
    TidesDB::Pager pager(testFileName, std::ios::out | std::ios::in | std::ios::binary);
    std::vector<uint8_t> data = {'h', 'e', 'l', 'l', 'o'};
    pager.Write(data);
    pager.Write(data);

    EXPECT_EQ(pager.PagesCount(), 2);
}

TEST_F(PagerTest, WriteWithCompression) {
    TidesDB::Pager pager(testFileName, std::ios::out | std::ios::in | std::ios::binary);
    std::vector<uint8_t> data = {'h', 'e', 'l', 'l', 'o'};
    int64_t pageNumber = pager.Write(data, true);

    std::vector<uint8_t> readData = pager.Read(pageNumber, true);
    EXPECT_EQ(data, readData);
}