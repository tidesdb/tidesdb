#include <filesystem>
#include <iostream>

#include "../../libtidesdb.h"

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

        // Choose a valid key, for example, key 5
        std::vector<uint8_t> key(4, 5);

        // Get key 5 before deletion
        std::vector<uint8_t> dat = lsmTree->Get(key);
        if (dat.empty()) {
            std::cerr << "Key not found on Get test for key: " << static_cast<int>(key[0])
                      << std::endl;
        } else {
            std::cout << "Key found Get test passed for key: " << static_cast<int>(key[0])
                      << std::endl;
        }

        // // Delete key 5
        // if (lsmTree->Delete(key)) {
        //     std::cout << "Key deleted Delete test passed for key: " << static_cast<int>(key[0])
        //     << std::endl;
        // } else {
        //     std::cerr << "Key not found Delete test failed for key: " << static_cast<int>(key[0])
        //     << std::endl;
        // }
        //
        // // Check if key 5 is deleted
        // dat = lsmTree->Get(key);
        // if (dat.empty()) {
        //     std::cout << "Key not found delete then get test passed for key: " <<
        //     static_cast<int>(key[0]) << std::endl;
        // } else {
        //     std::cerr << "Key found delete then get test failed for key: " <<
        //     static_cast<int>(key[0]) << std::endl;
        // }

        lsmTree->Close();

        // Remove the directory
        std::filesystem::remove_all(directory);

        return 0;

    } catch (const std::exception &e) {
        std::cerr << "Error initializing LSMT: " << e.what() << std::endl;
        return 1;
    }
}