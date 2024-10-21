#include <gtest/gtest.h>

#include <thread>

#include "../libtidesdb.hpp"

void insertKeyValue(TidesDB::AVLTree& tree, const std::vector<uint8_t>& key,
                    const std::vector<uint8_t>& value) {
    tree.Insert(key, value);
}

void deleteKey(TidesDB::AVLTree& tree, const std::vector<uint8_t>& key) { tree.Delete(key); }

TEST(AVLTreeConcurrentTest, ConcurrentInsertions) {
    TidesDB::AVLTree tree;
    std::vector<uint8_t> key1 = {'k', 'e', 'y', '1'};
    std::vector<uint8_t> value1 = {'v', 'a', 'l', 'u', 'e', '1'};
    std::vector<uint8_t> key2 = {'k', 'e', 'y', '2'};
    std::vector<uint8_t> value2 = {'v', 'a', 'l', 'u', 'e', '2'};

    std::thread t1(insertKeyValue, std::ref(tree), key1, value1);
    std::thread t2(insertKeyValue, std::ref(tree), key2, value2);

    t1.join();
    t2.join();

    EXPECT_EQ(tree.Get(key1), value1);
    EXPECT_EQ(tree.Get(key2), value2);
}

TEST(AVLTreeConcurrentTest, ConcurrentInsertionsAndDeletions) {
    TidesDB::AVLTree tree;
    std::vector<uint8_t> key1 = {'k', 'e', 'y', '1'};
    std::vector<uint8_t> value1 = {'v', 'a', 'l', 'u', 'e', '1'};
    std::vector<uint8_t> key2 = {'k', 'e', 'y', '2'};
    std::vector<uint8_t> value2 = {'v', 'a', 'l', 'u', 'e', '2'};

    tree.Insert(key1, value1);

    std::thread t1(insertKeyValue, std::ref(tree), key2, value2);
    std::thread t2(deleteKey, std::ref(tree), key1);

    t1.join();
    t2.join();

    EXPECT_EQ(tree.Get(key1), std::vector<uint8_t>());
    EXPECT_EQ(tree.Get(key2), value2);
}

TEST(AVLTreeConcurrentTest, ConcurrentClearAndInsert) {
    TidesDB::AVLTree tree;
    std::vector<uint8_t> key1 = {'k', 'e', 'y', '1'};
    std::vector<uint8_t> value1 = {'v', 'a', 'l', 'u', 'e', '1'};
    std::vector<uint8_t> key2 = {'k', 'e', 'y', '2'};
    std::vector<uint8_t> value2 = {'v', 'a', 'l', 'u', 'e', '2'};

    tree.Insert(key1, value1);

    std::thread t1(&TidesDB::AVLTree::Clear, &tree);
    std::thread t2(insertKeyValue, std::ref(tree), key2, value2);

    t1.join();
    t2.join();

    EXPECT_EQ(tree.Get(key1), std::vector<uint8_t>());
    EXPECT_EQ(tree.Get(key2), value2);
}