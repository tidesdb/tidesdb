#include <filesystem>
#include <iostream>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "../../libtidesdb.h"

void putValues(TidesDB::LSMT* lsmTree, int start, int end, std::mutex& mtx) {
    for (int i = start; i <= end; i++) {
        std::string keyStr = std::to_string(i);
        std::vector<uint8_t> key(keyStr.begin(), keyStr.end());
        std::vector<uint8_t> value(keyStr.begin(), keyStr.end());

        std::lock_guard<std::mutex> lock(mtx);
        lsmTree->Put(key, value);
    }
}

int main() {
    // Define parameters
    std::string directory = "./tidesdb_data";  // The directory for storing data
    std::filesystem::perms directoryPerm =
        std::filesystem::perms::owner_all | std::filesystem::perms::group_read;  // Permissions
    int memtableFlushSize = 100;
    int compactionInterval = 100;

    try {
        // Initialize the LSMT
        auto lsmTree =
            TidesDB::LSMT::New(directory, directoryPerm, memtableFlushSize, compactionInterval);

        std::mutex mtx;
        std::thread t1([&]() { putValues(lsmTree.get(), 1, 100, mtx); });
        std::thread t2([&]() { putValues(lsmTree.get(), 101, 200, mtx); });

        t1.join();
        t2.join();

        // Set of missing keys
        std::set<std::vector<uint8_t>> missingKeys;
        for (int i = 1; i <= 200; i++) {
            std::string keyStr = std::to_string(i);
            std::vector<uint8_t> key(keyStr.begin(), keyStr.end());
            missingKeys.insert(key);
        }

        // Retry until all key-value pairs are found
        while (!missingKeys.empty()) {
            for (auto it = missingKeys.begin(); it != missingKeys.end();) {
                std::vector<uint8_t> result = lsmTree->Get(*it);
                if (!result.empty() && result == *it) {  // Assuming value is the same as the key
                    it = missingKeys.erase(it);          // Remove found key from the set
                } else {
                    ++it;
                }
            }

            if (!missingKeys.empty()) {
                std::this_thread::sleep_for(std::chrono::seconds(1));  // Wait before retrying
            }
        }

        std::cout << "All key-value pairs found" << std::endl;

        lsmTree->Close();

        // Remove the directory
        std::filesystem::remove_all(directory);

        std::cout << "Test passed" << std::endl;

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Error initializing LSMT: " << e.what() << std::endl;
    }
}