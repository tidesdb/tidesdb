#include <gtest/gtest.h>

#include "../libtidesdb.hpp"

TEST(AVLNodeTest, ConstructorInitializesCorrectly) {
    std::vector<uint8_t> key = {'k', 'e', 'y'};
    std::vector<uint8_t> value = {'v', 'a', 'l', 'u', 'e'};
    auto expirationTime = std::chrono::steady_clock::now();

    TidesDB::AVLNode node(key, value);

    EXPECT_EQ(node.key, key);
    EXPECT_EQ(node.value, value);
    EXPECT_EQ(node.left, nullptr);
    EXPECT_EQ(node.right, nullptr);
    EXPECT_EQ(node.height, 1);
    EXPECT_EQ(node.expirationTime, expirationTime);
}

TEST(AVLTreeTest, InsertInsertsKeyValuePair) {
    TidesDB::AVLTree tree;
    std::vector<uint8_t> key = {'k', 'e', 'y'};
    std::vector<uint8_t> value = {'v', 'a', 'l', 'u', 'e'};

    tree.Insert(key, value);

    std::vector<uint8_t> retrievedValue = tree.Get(key);
    EXPECT_EQ(retrievedValue, value);
}

TEST(AVLTreeTest, DeleteDeletesKey) {
    TidesDB::AVLTree tree;
    std::vector<uint8_t> key = {'k', 'e', 'y'};
    std::vector<uint8_t> value = {'v', 'a', 'l', 'u', 'e'};

    tree.Insert(key, value);
    tree.Delete(key);

    // we expect empty vector to be returned
    EXPECT_EQ(tree.Get(key), std::vector<uint8_t>());
}

TEST(AVLTreeTest, GetRetrievesValue) {
    TidesDB::AVLTree tree;
    std::vector<uint8_t> key = {'k', 'e', 'y'};
    std::vector<uint8_t> value = {'v', 'a', 'l', 'u', 'e'};

    tree.Insert(key, value);

    std::vector<uint8_t> retrievedValue = tree.Get(key);
    EXPECT_EQ(retrievedValue, value);
}

TEST(AVLTreeTest, ClearClearsTree) {
    TidesDB::AVLTree tree;
    std::vector<uint8_t> key = {'k', 'e', 'y'};
    std::vector<uint8_t> value = {'v', 'a', 'l', 'u', 'e'};

    tree.Insert(key, value);
    tree.Clear();

    EXPECT_EQ(tree.Get(key), std::vector<uint8_t>());
}