#include <chrono>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include "../libtidesdb.h"

int main() {
    // Define parameters
    std::string directory = "./tidesdb_benchmark_data";
    std::filesystem::perms directoryPerm =
        std::filesystem::perms::owner_all | std::filesystem::perms::group_read;
    int memtableFlushSize = (1024 * 1024) * 128;  // 128MB in bytes
    int compactionInterval = 100;

    try {
        // Initialize the LSMT
        auto lsmTree =
            TidesDB::LSMT::New(directory, directoryPerm, memtableFlushSize, compactionInterval);

        // Benchmark Put operation
        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < 1000000; i++) {
            std::string keyStr = std::to_string(i);
            std::vector<uint8_t> key(keyStr.begin(), keyStr.end());
            std::vector<uint8_t> value(keyStr.begin(), keyStr.end());
            lsmTree->Put(key, value);
        }
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> putDuration = end - start;
        std::cout << "Put operation took: " << putDuration.count() << " seconds" << std::endl;

        lsmTree->Close();

        // Remove the directory
        std::filesystem::remove_all(directory);

    } catch (const std::exception &e) {
        std::cerr << "Error initializing LSMT: " << e.what() << std::endl;
    }

    return 0;
}