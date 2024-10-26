#include <gtest/gtest.h>

#include <filesystem>

#include "../libtidesdb.hpp"

class LSMTTest : public ::testing::Test {
   protected:
    std::string testDirectory = "test_db";

    void SetUp() override {
        // Create a test directory
        if (!std::filesystem::exists(testDirectory)) {
            std::filesystem::create_directory(testDirectory);
        }
    }

    void TearDown() override {
        // Remove the test directory and its contents
        std::filesystem::remove_all(testDirectory);
    }
};

TEST_F(LSMTTest, ConstructorTest) {
    auto lsmt = TidesDB::LSMT::New(testDirectory, std::filesystem::perms::all, 1024, 10);
    ASSERT_NE(lsmt, nullptr);

    // Close the LSMT
    lsmt->Close();
}

TEST_F(LSMTTest, PutAndGetTest) {
    auto lsmt = TidesDB::LSMT::New(testDirectory, std::filesystem::perms::all, 1024, 10);
    std::vector<uint8_t> key = {'k', 'e', 'y'};
    std::vector<uint8_t> value = {'v', 'a', 'l', 'u', 'e'};

    ASSERT_TRUE(lsmt->Put(key, value));
    auto retrievedValue = lsmt->Get(key);
    ASSERT_EQ(retrievedValue, value);

    // Close the LSMT
    lsmt->Close();
}

TEST_F(LSMTTest, DeleteTest) {
    auto lsmt = TidesDB::LSMT::New(testDirectory, std::filesystem::perms::all, 1024, 10);
    std::vector<uint8_t> key = {'k', 'e', 'y'};
    std::vector<uint8_t> value = {'v', 'a', 'l', 'u', 'e'};

    ASSERT_TRUE(lsmt->Put(key, value));
    ASSERT_TRUE(lsmt->Delete(key));
    auto retrievedValue = lsmt->Get(key);
    ASSERT_EQ(retrievedValue, std::vector<uint8_t>());

    // Close the LSMT
    lsmt->Close();
}

TEST_F(LSMTTest, CloseTest) {
    auto lsmt = TidesDB::LSMT::New(testDirectory, std::filesystem::perms::all, 1024, 10);
    std::vector<uint8_t> key = {'k', 'e', 'y'};
    std::vector<uint8_t> value = {'v', 'a', 'l', 'u', 'e'};

    ASSERT_TRUE(lsmt->Put(key, value));
    lsmt->Close();

    auto lsmt2 = TidesDB::LSMT::New(testDirectory, std::filesystem::perms::all, 1024, 10);
    auto retrievedValue = lsmt2->Get(key);
    ASSERT_EQ(retrievedValue, value);

    // Close the LSMT
    lsmt2->Close();
}