#include <chrono>  // Include for std::chrono::seconds
#include <filesystem>
#include <iostream>
#include <set>
#include <string>
#include <thread>  // Include for std::this_thread::sleep_for
#include <vector>

#include "../../libtidesdb.h"

int main() {
    // Define parameters
    std::string directory = "./tidesdb_data";  // The directory for storing data
    std::filesystem::perms directoryPerm =
        std::filesystem::perms::owner_all | std::filesystem::perms::group_read;  // Permissions
    int memtableFlushSize = 2;
    int compactionInterval = 3;

    try {
        // Initialize the LSMT
        auto lsmTree =
            TidesDB::LSMT::New(directory, directoryPerm, memtableFlushSize, compactionInterval);

        for (int i = 1; i <= 6; i++) {  // Insert fewer key-value pairs
            std::string keyStr = std::to_string(i);
            std::vector<uint8_t> key(keyStr.begin(), keyStr.end());
            std::vector<uint8_t> value(keyStr.begin(), keyStr.end());

            lsmTree->Put(key, value);
        }

        // Set of missing keys
        std::set<std::vector<uint8_t>> missingKeys;
        for (int i = 1; i <= 6; i++) {  // Adjust the range accordingly
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

        lsmTree->Close();

        std::cout << "Test passed" << std::endl;

        // Remove the directory
        std::filesystem::remove_all(directory);

        return 0;

    } catch (const std::exception &e) {
        std::cerr << "Error initializing LSMT: " << e.what() << std::endl;
    }
}