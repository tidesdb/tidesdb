#include <gtest/gtest.h>

#include <chrono>
#include <thread>

#include "../libtidesdb.hpp"

TEST(AVLTreeTTLTest, InsertWithTTL) {
    TidesDB::AVLTree tree;
    std::vector<uint8_t> key = {'k', 'e', 'y'};
    std::vector<uint8_t> value = {'v', 'a', 'l', 'u', 'e'};
    auto expirationTime = std::chrono::steady_clock::now() + std::chrono::seconds(1);

    tree.Insert(key, value, expirationTime);

    std::vector<uint8_t> retrievedValue = tree.Get(key);
    EXPECT_EQ(retrievedValue, value);
}

TEST(AVLTreeTTLTest, ExpireNode) {
    TidesDB::AVLTree tree;
    std::vector<uint8_t> key = {'k', 'e', 'y'};
    std::vector<uint8_t> value = {'v', 'a', 'l', 'u', 'e'};
    auto expirationTime = std::chrono::steady_clock::now() + std::chrono::seconds(1);

    tree.Insert(key, value, expirationTime);

    // Wait for the node to expire
    std::this_thread::sleep_for(std::chrono::seconds(2));

    std::vector<uint8_t> retrievedValue = tree.Get(key);
    EXPECT_EQ(retrievedValue, std::vector<uint8_t>());
}

TEST(AVLTreeTTLTest, NoExpiration) {
    TidesDB::AVLTree tree;
    std::vector<uint8_t> key = {'k', 'e', 'y'};
    std::vector<uint8_t> value = {'v', 'a', 'l', 'u', 'e'};

    tree.Insert(key, value);

    // Wait for some time to ensure no expiration
    std::this_thread::sleep_for(std::chrono::seconds(2));

    std::vector<uint8_t> retrievedValue = tree.Get(key);
    EXPECT_EQ(retrievedValue, value);
}

TEST(AVLTreeTTLTest, UpdateTTL) {
    TidesDB::AVLTree tree;
    std::vector<uint8_t> key = {'k', 'e', 'y'};
    std::vector<uint8_t> value = {'v', 'a', 'l', 'u', 'e'};
    auto expirationTime = std::chrono::steady_clock::now() + std::chrono::seconds(1);

    tree.Insert(key, value, expirationTime);

    // Update the TTL
    auto newExpirationTime = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    tree.Insert(key, value, newExpirationTime);

    // Wait for the original expiration time to pass
    std::this_thread::sleep_for(std::chrono::seconds(2));

    std::vector<uint8_t> retrievedValue = tree.Get(key);
    EXPECT_EQ(retrievedValue, value);
}