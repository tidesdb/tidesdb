#include <iostream>
#include "../../library.h"


int main() {
    // Define parameters
    std::string directory = "./tidesdb_data"; // The directory for storing data
    std::filesystem::perms directoryPerm = std::filesystem::perms::owner_all | std::filesystem::perms::group_read; // Permissions
    int memtableFlushSize = 10 * 1024; // Example flush size (10 KB)
    int compactionInterval = 5; // Example compaction interval (in seconds)
    int minimumSSTables = 2; // Minimum SSTables required

    try {
        // Initialize the LSMT
        auto lsmTree = TidesDB::LSMT::New(directory, directoryPerm, memtableFlushSize, compactionInterval, minimumSSTables);


        // Insert 20kb of data
        for (int i = 0; i < 20; i++) {
            std::vector<uint8_t> key(4, i);
            std::vector<uint8_t> value(1024, i);


            lsmTree->Put(key, value);
        }


        lsmTree->Close();

    } catch (const std::exception& e) {
        std::cerr << "Error initializing LSMT: " << e.what() << std::endl;
    }

}
