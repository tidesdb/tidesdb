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

TEST_F(PagerTest, WriteAndReadMultiplePages) {
    TidesDB::Pager pager(testFileName, std::ios::out | std::ios::in | std::ios::binary);
    std::vector<uint8_t> data(4096, 'a');
    int64_t pageNumber1 = pager.Write(data);
    int64_t pageNumber2 = pager.Write(data);

    std::vector<uint8_t> readData1 = pager.Read(pageNumber1);
    std::vector<uint8_t> readData2 = pager.Read(pageNumber2);

    EXPECT_EQ(data, readData1);
    EXPECT_EQ(data, readData2);
}

TEST_F(PagerTest, WriteAndReadWithOverflow) {
    TidesDB::Pager pager(testFileName, std::ios::out | std::ios::in | std::ios::binary);
    std::vector<uint8_t> largeData(8192,
                                   'b');  // Page size is 4096 bytes, this will overflow to 2 pages
    int64_t pageNumber = pager.Write(largeData);

    std::vector<uint8_t> readData = pager.Read(pageNumber);

    EXPECT_EQ(largeData, readData);
}