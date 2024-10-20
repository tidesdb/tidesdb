#include <chrono>
#include <iostream>
#include <mutex>
#include <random>
#include <thread>
#include <vector>

#include "../../libtidesdb.h"

void randomInserts(TidesDB::AVLTree &tree, int num_operations) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (int i = 0; i < num_operations; ++i) {
        std::vector<uint8_t> key = {static_cast<uint8_t>(dis(gen))};
        std::vector<uint8_t> value = {static_cast<uint8_t>(dis(gen))};
        tree.insert(key, value);
    }
}

void randomDeletes(TidesDB::AVLTree &tree, int num_operations) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (int i = 0; i < num_operations; ++i) {
        std::vector<uint8_t> key = {static_cast<uint8_t>(dis(gen))};
        tree.deleteKV(key);
    }
}

int main() {
    // Test AVL tree
    TidesDB::AVLTree tree;

    // Number of operations for each thread
    int num_operations = 100000;

    // Create threads for random inserts and deletes
    std::thread insert_thread(randomInserts, std::ref(tree), num_operations);
    std::thread delete_thread(randomDeletes, std::ref(tree), num_operations);

    // Wait for both threads to finish
    insert_thread.join();
    delete_thread.join();

    // Final size of the tree
    std::cout << "Final size of the tree: " << tree.GetSize() << std::endl;

    return 0;
}