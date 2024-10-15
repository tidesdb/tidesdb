#include <iostream>
#include "../../library.h"


int main() {
    // Define parameters
    std::string directory = "./tidesdb_data"; // The directory for storing data
    std::filesystem::perms directoryPerm = std::filesystem::perms::owner_all | std::filesystem::perms::group_read; // Permissions
    int memtableFlushSize = 10 * 1024; // Example flush size (10 KB)
    int compactionInterval = 4; // Example compaction interval (amounr of ss tables before compaction)
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

        // Get key 5555
        std::vector<uint8_t> key(4, 5);

        std::vector<uint8_t> dat = lsmTree->Get(key);

        if (dat.size() == 0) {
            std::cerr << "Key not found" << std::endl;
        } else {
            std::cout << "Key found" << std::endl;
        }




        lsmTree->Close();

        return 0;


    } catch (const std::exception& e) {
        std::cerr << "Error initializing LSMT: " << e.what() << std::endl;
    }

}
