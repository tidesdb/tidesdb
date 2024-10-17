#include <chrono>
#include <iostream>
#include <vector>

#include "../../libtidesdb.h"

int main() {
    TidesDB::SkipList skipList(12, 0.5);

    // Insert key-value pairs
    skipList.insert({1, 2, 3}, {10, 20, 30});
    skipList.insert({4, 5, 6}, {40, 50, 60});
    skipList.insert({2, 3, 4}, {20, 30, 40});

    // Test insertion
    if (skipList.get({1, 2, 3}) == std::vector<uint8_t>({10, 20, 30}) &&
        skipList.get({4, 5, 6}) == std::vector<uint8_t>({40, 50, 60}) &&
        skipList.get({2, 3, 4}) == std::vector<uint8_t>({20, 30, 40})) {
        std::cout << "Insert test passed" << std::endl;
    } else {
        std::cout << "Insert test failed" << std::endl;
    }

    // Delete a key
    skipList.deleteKV({1, 2, 3});

    // Test deletion
    if (skipList.get({1, 2, 3}).empty() &&
        skipList.get({4, 5, 6}) == std::vector<uint8_t>({40, 50, 60}) &&
        skipList.get({2, 3, 4}) == std::vector<uint8_t>({20, 30, 40})) {
        std::cout << "Delete test passed" << std::endl;
    } else {
        std::cout << "Delete test failed" << std::endl;
    }

    // Test retrieval
    std::vector<uint8_t> value = skipList.get({4, 5, 6});
    if (value == std::vector<uint8_t>({40, 50, 60})) {
        std::cout << "Get test passed" << std::endl;
    } else {
        std::cout << "Get test failed" << std::endl;
    }

    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000000; ++i) {
        std::vector<uint8_t> key = {
            static_cast<uint8_t>((i >> 16) & 0xFF),  // First byte
            static_cast<uint8_t>((i >> 8) & 0xFF),   // Second byte
            static_cast<uint8_t>(i & 0xFF)           // Third byte
        };
        std::vector<uint8_t> value = {static_cast<uint8_t>(i)};
        skipList.insert(key, value);
    }

    // print size
    std::cout << "Size of SkipList: " << skipList.getSize() << std::endl;

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - start;
    std::cout << "Time taken to insert 1,000,000 key-value pairs: " << duration.count()
              << " seconds" << std::endl;

    return 0;
}