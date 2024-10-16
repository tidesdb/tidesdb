#include <iostream>

#include "../../library.h"

int main() {
    // Test AVL tree
    TidesDB::AVLTree tree;
    //
    // // Insert some key-value pairs
    tree.insert({1, 2, 3}, {10, 20, 30});
    tree.insert({4, 5, 6}, {40, 50, 60});
    tree.insert({2, 3, 4}, {20, 30, 40});

    // Get keys
    if (tree.GetSize() == 3) {
        std::cout << "Insert test passed" << std::endl;
    } else {
        std::cout << "Insert test failed" << std::endl;
    }

    // Delete a key
    tree.deleteKV({1, 2, 3});

    // Get keys
    if (tree.GetSize() == 2) {
        std::cout << "Delete test passed" << std::endl;
    } else {
        std::cout << "Delete test failed" << std::endl;
    }

    // Check if key exists
    std::vector<uint8_t> value = tree.Get({4, 5, 6});

    if (value == std::vector<uint8_t>({40, 50, 60})) {
        std::cout << "Get after delete test passed" << std::endl;
    } else {
        std::cout << "Get after delete test failed" << std::endl;
    }
}
