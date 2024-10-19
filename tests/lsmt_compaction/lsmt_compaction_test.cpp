#include <chrono>
#include <filesystem>
#include <iostream>
#include <set>
#include <string>
#include <thread>
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

        for (int i = 1; i <= 8; i++) {  // Insert fewer key-value pairs
            std::string keyStr = std::to_string(i);
            std::vector<uint8_t> key(keyStr.begin(), keyStr.end());
            std::vector<uint8_t> value(keyStr.begin(), keyStr.end());

            lsmTree->Put(key, value);
            std::cout << "Inserted key: " << keyStr << ", value: " << keyStr << std::endl;
        }

        // Wait for background threads to finish flushing and compacting
        std::this_thread::sleep_for(std::chrono::seconds(5));

        std::cout << "Keys and values after compaction:" << std::endl;
        for (int i = 1; i <= 8; i++) {
            std::string keyStr = std::to_string(i);
            std::vector<uint8_t> key(keyStr.begin(), keyStr.end());
            auto value = lsmTree->Get(key);
            if (value.data()) {
                std::string valueStr(value.begin(), value.end());
                std::cout << keyStr << ": " << valueStr << std::endl;
            } else {
                std::cout << keyStr << ": not found" << std::endl;
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