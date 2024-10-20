#include <chrono>
#include <iostream>
#include <mutex>
#include <random>
#include <set>
#include <thread>
#include <vector>

#include "../../libtidesdb.hpp"

void predefinedInserts(
    TidesDB::AVLTree &tree,
    const std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> &inserts) {
    for (const auto &kv : inserts) {
        tree.Insert(kv.first, kv.second);
    }
}

void predefinedDeletes(TidesDB::AVLTree &tree, const std::vector<std::vector<uint8_t>> &deletes) {
    for (const auto &key : deletes) {
        tree.Delete(key);
    }
}

void verifyData(
    TidesDB::AVLTree &tree,
    const std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> &expected) {
    std::cout << "Verifying data in AVL tree:" << std::endl;
    bool allMatched = true;
    for (const auto &kv : expected) {
        std::vector<uint8_t> value = tree.Get(kv.first);
        if (value != kv.second) {
            allMatched = false;
            std::cout << "Mismatch for key: ";
            for (auto byte : kv.first) {
                std::cout << std::hex << static_cast<int>(byte) << " ";
            }
            std::cout << "Expected value: ";
            for (auto byte : kv.second) {
                std::cout << std::hex << static_cast<int>(byte) << " ";
            }
            std::cout << "Actual value: ";
            for (auto byte : value) {
                std::cout << std::hex << static_cast<int>(byte) << " ";
            }
            std::cout << std::dec << std::endl;
        }
    }
    if (allMatched) {
        std::cout << "All key-value pairs matched expected values." << std::endl;
    }
}

int main() {
    // Test AVL tree
    TidesDB::AVLTree tree;

    // Predefined key-value pairs for insertion
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> inserts = {
        {{1}, {10}}, {{2}, {20}}, {{3}, {30}}, {{4}, {40}}, {{5}, {50}}};

    // Predefined keys for deletion
    std::vector<std::vector<uint8_t>> deletes = {{2}, {4}};

    // Expected final key-value pairs
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> expected = {
        {{1}, {10}}, {{3}, {30}}, {{5}, {50}}};

    // Create threads for predefined inserts and deletes
    std::thread insert_thread(predefinedInserts, std::ref(tree), std::cref(inserts));
    std::thread delete_thread(predefinedDeletes, std::ref(tree), std::cref(deletes));

    // Wait for both threads to finish
    insert_thread.join();
    delete_thread.join();

    // Verify the data in the AVL tree
    verifyData(tree, expected);

    return 0;
}