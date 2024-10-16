#include <filesystem>
#include <iostream>
#include <thread>
#include <vector>

#include "../../libtidesdb.h"

void writeData(TidesDB::LSMT* lsmTree, int start, int end) {
    for (int i = start; i < end; ++i) {
        std::vector<uint8_t> key(4, i);
        std::vector<uint8_t> value(1024, i);
        lsmTree->Put(key, value);
    }
}

int main() {
    // Define parameters
    std::string directory = "./tidesdb_data";  // The directory for storing data
    std::filesystem::perms directoryPerm =
        std::filesystem::perms::owner_all | std::filesystem::perms::group_read;  // Permissions
    int memtableFlushSize = 10 * 1024;  // Example flush size (10 KB)
    int compactionInterval = 2;  // Lower compaction interval to trigger compactions more frequently

    try {
        // Initialize the LSMT
        auto lsmTree =
            TidesDB::LSMT::New(directory, directoryPerm, memtableFlushSize, compactionInterval);

        // Create multiple threads to write data concurrently
        int numThreads = 4;
        int dataPerThread =
            100;  // Increase the amount of data per thread to trigger multiple compactions
        std::vector<std::thread> threads;

        for (int i = 0; i < numThreads; ++i) {
            threads.emplace_back(writeData, lsmTree.get(), i * dataPerThread,
                                 (i + 1) * dataPerThread);
        }

        // Wait for all threads to finish
        for (auto& t : threads) {
            t.join();
        }

        // Get key 5555
        std::vector<uint8_t> key(4, 5);
        std::vector<uint8_t> dat = lsmTree->Get(key);

        if (dat.size() == 0) {
            std::cerr << "Key not found Get test failed" << std::endl;
        } else {
            std::cout << "Key found Get test passed" << std::endl;
        }

        // Delete key 5555
        if (lsmTree->Delete(key)) {
            std::cout << "Key deleted Delete test passed" << std::endl;
        } else {
            std::cerr << "Key not found Delete test failed" << std::endl;
        }

        // Check if key 5555 is deleted
        dat = lsmTree->Get(key);

        if (dat.size() == 0) {
            std::cout << "Key not found delete then get test passed" << std::endl;
        } else {
            std::cerr << "Key found delete then get test failed" << std::endl;
        }

        lsmTree->Close();

        // Remove the directory
        std::filesystem::remove_all(directory);

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Error initializing LSMT: " << e.what() << std::endl;
    }
}