#include <chrono>
#include <filesystem>
#include <iostream>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "../../libtidesdb.hpp"

int main() {
    // Define parameters
    std::string directory = "./tidesdb_data";  // The directory for storing data
    std::filesystem::perms directoryPerm =
        std::filesystem::perms::owner_all | std::filesystem::perms::group_read;  // Permissions
    int memtableFlushSize = 10 * 1024;  // Example flush size (10 KB)
    int compactionInterval = 8;

    try {
        // Initialize the LSMT
        auto lsmTree =
            TidesDB::LSMT::New(directory, directoryPerm, memtableFlushSize, compactionInterval);

        // Insert 20 KB of data with valid keys (0-19)
        for (int i = 0; i < 20; i++) {
            std::vector<uint8_t> key(4, i);       // Key is based on the loop index
            std::vector<uint8_t> value(1024, i);  // Example value

            lsmTree->Put(key, value);
            std::cout << "Inserted key: " << static_cast<int>(key[0])
                      << std::endl;  // Debug statement
        }

        // Set of missing keys
        std::set<std::vector<uint8_t>> missingKeys;
        for (int i = 0; i < 20; i++) {
            std::vector<uint8_t> key(4, i);
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

        std::cout << "closing the LSMT" << std::endl;

        lsmTree->Close();

        // Remove the directory
        std::filesystem::remove_all(directory);

        return 0;

    } catch (const std::exception &e) {
        std::cerr << "Error initializing LSMT: " << e.what() << std::endl;
        return 1;
    }
}